// SPDX-License-Identifier: MPL-2.0

//! The `/dev/agent_ctl` device.
//!
//! An agent shim inside the VM uses it to mark tool-call boundaries. To run a tool call,
//! the shim forks a child that begins a TCT and then executes the tool; after the tool
//! exits, the shim ends the TCT, reads its effects, commits its data (possibly while the
//! model handles the tool result), and releases it. See [`Tct`] for how
//! processes are attributed to a TCT. A commit waits until no TCT is running, so a shim that
//! runs tool calls in parallel ends all of them before committing any.
//!
//! To tag a snapshot of an epoch on the host, the shim commits with
//! `AGENT_CTL_TCT_COMMIT_HOLD`, which keeps the commit gate closed so that no TCT begins until
//! the shim opens it with `AGENT_CTL_TCT_COMMIT_DONE` (or closes the file) after the host has
//! taken the snapshot.
//!
//! Controlling a TCT (beginning, ending, reading its effects or processes, committing and
//! releasing it) requires `CAP_SYS_ADMIN`, and is refused for processes that are already in a
//! TCT, so a tool cannot leave its TCT or control it from the inside.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use aster_core::{
    current,
    device::{Device, DeviceType, registry::char},
    dispatch_ioctl,
    events::IoEvents,
    fs::{
        devtmpfs::DevtmpfsNodeMeta,
        file::{PerOpenFileOps, StatusFlags},
        vfs::{inode::FileOps, path::Path},
    },
    ioc,
    prelude::*,
    process::{
        UserNamespace,
        credentials::capabilities::CapSet,
        posix_thread::AsPosixThread,
        signal::{PollHandle, Pollable},
    },
    security::lsm::hooks::{self as lsm_hook, CapableContext},
    util::ioctl::{InData, InOutData, NoData, OutData, RawIoctl},
};
use device_id::{DeviceId, MajorId, MinorId};
use ostd::{
    mm::{VmIo, VmReader, VmWriter},
    task::Task,
};

use crate::tct::{Tct, TctFlags};

/// The major number of misc devices.
const MISC_MAJOR: u16 = 10;
/// A minor number from the range that Linux reserves for local use.
const AGENT_CTL_MINOR: u32 = 240;

#[derive(Debug)]
struct AgentCtlDevice {
    id: DeviceId,
}

impl Device for AgentCtlDevice {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        self.id
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsNodeMeta> {
        Some(DevtmpfsNodeMeta::new("agent_ctl").unwrap())
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(AgentCtlFile {
            holds_commit_gate: AtomicBool::new(false),
        }))
    }
}

struct AgentCtlFile {
    /// Whether a commit through this file holds the commit gate.
    holds_commit_gate: AtomicBool,
}

impl Drop for AgentCtlFile {
    fn drop(&mut self) {
        if *self.holds_commit_gate.get_mut() {
            Tct::open_commit_gate();
        }
    }
}

impl Pollable for AgentCtlFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        mask & (IoEvents::IN | IoEvents::OUT)
    }
}

impl FileOps for AgentCtlFile {
    fn read_at(
        &self,
        _offset: usize,
        _writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "the agent control device is not readable")
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "the agent control device is not writable")
    }
}

impl PerOpenFileOps for AgentCtlFile {
    fn check_seekable(&self) -> Result<()> {
        return_errno_with_message!(Errno::ESPIPE, "seek is not supported")
    }

    fn is_offset_aware(&self) -> bool {
        false
    }

    fn ioctl(&self, _path: &Path, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl_defs::*;

        let task = Task::current().unwrap();
        let posix_thread = task.as_posix_thread().unwrap();
        let process = current!();

        // Checks that the caller may control a TCT.
        let check_controller = || {
            lsm_hook::on_capable(CapableContext::new(
                UserNamespace::get_init_singleton().as_ref(),
                posix_thread,
                CapSet::SYS_ADMIN,
            ))?;
            if Tct::of(&process).is_some() {
                return_errno_with_message!(Errno::EPERM, "the caller is in a TCT");
            }
            Ok(())
        };

        dispatch_ioctl!(match raw_ioctl {
            cmd @ TctBegin => {
                let mut args: TctBeginArgs = cmd.read()?;
                let flags = TctFlags::from_bits(args.flags)
                    .filter(|_| args.reserved == 0)
                    .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid TCT flags"))?;
                check_controller()?;
                // Write the ID first, so a failed write does not leave the caller in a TCT
                // that it cannot identify.
                let tct = Tct::new(flags);
                args.id = tct.id();
                cmd.write(&args)?;
                tct.begin(&process).map_err(restart_on_signal)?;
                Ok(0)
            }
            cmd @ TctEnd => {
                let mut end: TctEndArgs = cmd.read()?;
                check_controller()?;
                let tct = Tct::get(end.id)?;
                // Write the output first, so a failed write does not leave the TCT ended
                // without the caller knowing it.
                end.nr_live_processes = tct.nr_live_processes() as u64;
                cmd.write(&end)?;
                tct.end()?;
                Ok(0)
            }
            cmd @ TctGet => {
                cmd.write(&Tct::of(&process).map_or(0, |tct| tct.id()))?;
                Ok(0)
            }
            cmd @ TctEffects => {
                cmd.with_data_ptr(|args_ptr| {
                    let args: TctBufferArgs = args_ptr.read()?;
                    check_controller()?;
                    let tct = Tct::get(args.id)?;
                    let (args, output) = args.fill(tct.export_effects());
                    args_ptr.write(&args)?;
                    args_ptr.vm().write_bytes(args.buf as usize, &output?)?;
                    Ok(0)
                })
            }
            cmd @ TctProcesses => {
                cmd.with_data_ptr(|args_ptr| {
                    let args: TctBufferArgs = args_ptr.read()?;
                    check_controller()?;
                    let tct = Tct::get(args.id)?;
                    let (args, output) = args.fill(
                        tct.live_processes()
                            .into_iter()
                            .flat_map(u32::to_ne_bytes)
                            .collect(),
                    );
                    args_ptr.write(&args)?;
                    args_ptr.vm().write_bytes(args.buf as usize, &output?)?;
                    Ok(0)
                })
            }
            cmd @ TctCommit => {
                let mut args: TctCommitArgs = cmd.read()?;
                let should_hold = match args.flags {
                    0 => false,
                    TCT_COMMIT_HOLD => true,
                    _ => return_errno_with_message!(Errno::EINVAL, "invalid commit flags"),
                };
                if args.reserved != 0 {
                    return_errno_with_message!(Errno::EINVAL, "invalid commit flags");
                }
                check_controller()?;
                let tct = Tct::get(args.id)?;
                // Check that the output can be written before committing.
                cmd.write(&args)?;
                // The commit would wait for the gate that this file holds forever.
                if self.holds_commit_gate.load(Ordering::Acquire) {
                    return_errno_with_message!(Errno::EBUSY, "the file holds the commit gate");
                }
                let outcome = tct.commit(should_hold).map_err(restart_on_signal)?;
                if outcome.holds_gate {
                    self.holds_commit_gate.store(true, Ordering::Release);
                }
                args.flags = if outcome.holds_gate {
                    TCT_COMMIT_HOLD
                } else {
                    0
                };
                args.epoch = outcome.epoch;
                // If the output cannot be written now, the data is still durable, and the gate
                // stays held until `AGENT_CTL_TCT_COMMIT_DONE` or until the file is closed.
                cmd.write(&args)?;
                Ok(0)
            }
            _cmd @ TctCommitDone => {
                check_controller()?;
                if !self.holds_commit_gate.swap(false, Ordering::AcqRel) {
                    return_errno_with_message!(
                        Errno::EINVAL,
                        "the file does not hold the commit gate"
                    );
                }
                Tct::open_commit_gate();
                Ok(0)
            }
            cmd @ TctRelease => {
                let id = cmd.read()?;
                check_controller()?;
                Tct::release(id)?;
                Ok(0)
            }
            _ => return_errno_with_message!(Errno::ENOTTY, "the ioctl command is unknown"),
        })
    }
}

/// Restarts an ioctl interrupted by a signal if the signal handler allows it.
///
/// This is only used for ioctls that can be retried without side effects.
fn restart_on_signal(err: Error) -> Error {
    match err.error() {
        Errno::EINTR => Error::new(Errno::ERESTARTSYS),
        _ => err,
    }
}

/// The argument of `AGENT_CTL_TCT_BEGIN`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct TctBeginArgs {
    /// The flags of the TCT (input), see [`TctFlags`].
    flags: u32,
    reserved: u32,
    /// The ID of the TCT (output).
    id: u64,
}

/// Keeps the commit gate closed after a commit, see [`Tct::commit`].
const TCT_COMMIT_HOLD: u32 = 1 << 0;

/// The argument of `AGENT_CTL_TCT_COMMIT`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct TctCommitArgs {
    /// The ID of the TCT to commit (input).
    id: u64,
    /// The commit flags (input), and `TCT_COMMIT_HOLD` if the caller holds the commit gate
    /// (output).
    flags: u32,
    reserved: u32,
    /// The epoch of the commit that covers the TCT (output).
    epoch: u64,
}

/// The argument of `AGENT_CTL_TCT_END`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct TctEndArgs {
    /// The ID of the TCT to end (input).
    id: u64,
    /// The number of processes in the TCT that have not exited (output).
    nr_live_processes: u64,
}

/// The argument of `AGENT_CTL_TCT_EFFECTS` and `AGENT_CTL_TCT_PROCESSES`.
///
/// `AGENT_CTL_TCT_EFFECTS` writes the effects to `buf` in the format of [`Tct::export_effects`].
/// `AGENT_CTL_TCT_PROCESSES` writes the PIDs of the processes in the TCT that have not exited
/// to `buf`, as native-endian `u32` values in ascending order.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct TctBufferArgs {
    /// The ID of the TCT (input).
    id: u64,
    /// The user buffer to write the effects to (input).
    buf: u64,
    /// The length of `buf` (input), and the length of the effects (output).
    ///
    /// If `buf` is too short, nothing is written to it and `ERANGE` is returned.
    len: u64,
}

impl TctBufferArgs {
    /// Sets `len` to the length of `output`, and returns `output` if it fits in the buffer, or
    /// `ERANGE` otherwise, in which case nothing is written to the buffer.
    fn fill(mut self, output: Vec<u8>) -> (Self, Result<Vec<u8>>) {
        let buf_len = self.len;
        self.len = output.len() as u64;
        if buf_len < self.len {
            return (
                self,
                Err(Error::with_message(
                    Errno::ERANGE,
                    "the buffer is too small",
                )),
            );
        }
        (self, Ok(output))
    }
}

mod ioctl_defs {
    use super::*;

    // TCT IDs start from 1; `AGENT_CTL_TCT_GET` returns 0 outside a TCT.
    pub(super) type TctBegin   = ioc!(AGENT_CTL_TCT_BEGIN,   0xA7, 1, InOutData<TctBeginArgs>);
    pub(super) type TctEnd     = ioc!(AGENT_CTL_TCT_END,     0xA7, 2, InOutData<TctEndArgs>);
    pub(super) type TctGet     = ioc!(AGENT_CTL_TCT_GET,     0xA7, 3, OutData<u64>);
    pub(super) type TctEffects = ioc!(AGENT_CTL_TCT_EFFECTS, 0xA7, 4, InOutData<TctBufferArgs>);
    pub(super) type TctRelease = ioc!(AGENT_CTL_TCT_RELEASE, 0xA7, 5, InData<u64>);
    pub(super) type TctCommit  = ioc!(AGENT_CTL_TCT_COMMIT,  0xA7, 6, InOutData<TctCommitArgs>);
    pub(super) type TctCommitDone = ioc!(AGENT_CTL_TCT_COMMIT_DONE, 0xA7, 7, NoData);
    pub(super) type TctProcesses = ioc!(AGENT_CTL_TCT_PROCESSES, 0xA7, 8, InOutData<TctBufferArgs>);
}

pub(crate) fn init() -> Result<()> {
    let id = DeviceId::new(MajorId::new(MISC_MAJOR), MinorId::new(AGENT_CTL_MINOR));
    char::register(Arc::new(AgentCtlDevice { id }))
}
