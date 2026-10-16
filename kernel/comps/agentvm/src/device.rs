// SPDX-License-Identifier: MPL-2.0

//! The `/dev/agent_ctl` device.
//!
//! An agent shim inside the VM uses it to mark tool-call boundaries. To run a tool call,
//! the shim forks a child that begins a TCT and then executes the tool; after the tool
//! exits, the shim ends the TCT, reads its effects and releases it. See [`Tct`] for how
//! processes are attributed to a TCT.
//!
//! Controlling a TCT (beginning, ending, reading its effects and releasing it) requires
//! `CAP_SYS_ADMIN`, and is refused for processes that are already in a TCT, so a tool cannot
//! leave its TCT or control it from the inside.

use alloc::{boxed::Box, sync::Arc};

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
    util::ioctl::{InData, InOutData, OutData, RawIoctl},
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
        Ok(Box::new(AgentCtlFile))
    }
}

struct AgentCtlFile;

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
                    .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid TCT flags"))?;
                check_controller()?;
                // Write the ID first, so a failed write does not leave the caller in a TCT
                // that it cannot identify.
                let tct = Tct::new(flags);
                args.id = tct.id();
                cmd.write(&args)?;
                tct.begin(&process)?;
                Ok(0)
            }
            cmd @ TctEnd => {
                let mut end: TctEndArgs = cmd.read()?;
                check_controller()?;
                let tct = Tct::get(end.id)?;
                tct.end()?;
                end.nr_live_processes = tct.nr_live_processes() as u64;
                cmd.write(&end)?;
                Ok(0)
            }
            cmd @ TctGet => {
                cmd.write(&Tct::of(&process).map_or(0, |tct| tct.id()))?;
                Ok(0)
            }
            cmd @ TctEffects => {
                cmd.with_data_ptr(|args_ptr| {
                    let mut args: TctEffectsArgs = args_ptr.read()?;
                    check_controller()?;
                    let effects = Tct::get(args.id)?.export_effects();
                    let buf_len = args.len;
                    args.len = effects.len() as u64;
                    args_ptr.write(&args)?;
                    if (buf_len as usize) < effects.len() {
                        return_errno_with_message!(Errno::ERANGE, "the buffer is too small");
                    }
                    args_ptr.vm().write_bytes(args.buf as usize, &effects)?;
                    Ok(0)
                })
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

/// The argument of `AGENT_CTL_TCT_END`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct TctEndArgs {
    /// The ID of the TCT to end (input).
    id: u64,
    /// The number of processes in the TCT that have not exited (output).
    nr_live_processes: u64,
}

/// The argument of `AGENT_CTL_TCT_EFFECTS`.
///
/// The effects are written to `buf` in the format of [`Tct::export_effects`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct TctEffectsArgs {
    /// The ID of the TCT (input).
    id: u64,
    /// The user buffer to write the effects to (input).
    buf: u64,
    /// The length of `buf` (input), and the length of the effects (output).
    ///
    /// If `buf` is too short, nothing is written to it and `ERANGE` is returned.
    len: u64,
}

mod ioctl_defs {
    use super::*;

    // TCT IDs start from 1; `AGENT_CTL_TCT_GET` returns 0 outside a TCT.
    pub(super) type TctBegin   = ioc!(AGENT_CTL_TCT_BEGIN,   0xA7, 1, InOutData<TctBeginArgs>);
    pub(super) type TctEnd     = ioc!(AGENT_CTL_TCT_END,     0xA7, 2, InOutData<TctEndArgs>);
    pub(super) type TctGet     = ioc!(AGENT_CTL_TCT_GET,     0xA7, 3, OutData<u64>);
    pub(super) type TctEffects = ioc!(AGENT_CTL_TCT_EFFECTS, 0xA7, 4, InOutData<TctEffectsArgs>);
    pub(super) type TctRelease = ioc!(AGENT_CTL_TCT_RELEASE, 0xA7, 5, InData<u64>);
}

pub(crate) fn init() -> Result<()> {
    let id = DeviceId::new(MajorId::new(MISC_MAJOR), MinorId::new(AGENT_CTL_MINOR));
    char::register(Arc::new(AgentCtlDevice { id }))
}
