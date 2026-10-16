// SPDX-License-Identifier: MPL-2.0

//! The `/dev/agent_ctl` device.
//!
//! An agent shim inside the VM uses it to mark tool-call boundaries. To run a tool call,
//! the shim forks a child that begins a TCT and then executes the tool; after the tool
//! exits, the shim ends the TCT. See [`Tct`] for how processes are attributed to a TCT.
//!
//! Controlling a TCT (beginning, ending, reading its effects and releasing it) requires
//! `CAP_SYS_ADMIN`, and is refused for processes that are already in a TCT, so a tool cannot
//! leave its TCT or control it from the inside.

use device_id::{DeviceId, MinorId};
use ostd::mm::VmIo;

use crate::{
    context::current_userspace,
    device::{Device, DeviceType, registry::char},
    dispatch_ioctl,
    events::IoEvents,
    fs::{
        devtmpfs::DevtmpfsNodeMeta,
        file::{PerOpenFileOps, StatusFlags},
        vfs::{inode::FileOps, path::Path},
    },
    prelude::*,
    process::{
        Tct, UserNamespace,
        credentials::capabilities::CapSet,
        posix_thread::AsPosixThread,
        signal::{PollHandle, Pollable},
    },
    security::lsm::hooks as lsm_hooks,
    util::ioctl::RawIoctl,
};

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

        let current = current_thread!();
        let posix_thread = current.as_posix_thread().unwrap();
        let process = posix_thread.process();

        // Checks that the caller may control a TCT.
        let check_controller = || {
            lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
                UserNamespace::get_init_singleton().as_ref(),
                posix_thread,
                CapSet::SYS_ADMIN,
            ))?;
            if process.tct().is_some() {
                return_errno_with_message!(Errno::EPERM, "the caller is in a TCT");
            }
            Ok(())
        };

        dispatch_ioctl!(match raw_ioctl {
            cmd @ TctBegin => {
                check_controller()?;
                let tct = Tct::begin(&process)?;
                cmd.write(&tct.id())?;
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
                cmd.write(&process.tct().map_or(0, |tct| tct.id()))?;
                Ok(0)
            }
            cmd @ TctEffects => {
                let mut args: TctEffectsArgs = cmd.read()?;
                check_controller()?;
                let effects = Tct::get(args.id)?.export_effects();
                let buf_len = args.len;
                args.len = effects.len() as u64;
                cmd.write(&args)?;
                if (buf_len as usize) < effects.len() {
                    return_errno_with_message!(Errno::ERANGE, "the buffer is too small");
                }
                current_userspace!().write_bytes(args.buf as Vaddr, &effects)?;
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
    use super::{TctEffectsArgs, TctEndArgs};
    use crate::{
        ioc,
        util::ioctl::{InData, InOutData, OutData},
    };

    // TCT IDs start from 1; `AGENT_CTL_TCT_GET` returns 0 outside a TCT.
    pub(super) type TctBegin = ioc!(AGENT_CTL_TCT_BEGIN, 0xA7, 1, OutData<u64>);
    pub(super) type TctEnd   = ioc!(AGENT_CTL_TCT_END,   0xA7, 2, InOutData<TctEndArgs>);
    pub(super) type TctGet   = ioc!(AGENT_CTL_TCT_GET,   0xA7, 3, OutData<u64>);
    pub(super) type TctEffects = ioc!(AGENT_CTL_TCT_EFFECTS, 0xA7, 4, InOutData<TctEffectsArgs>);
    pub(super) type TctRelease = ioc!(AGENT_CTL_TCT_RELEASE, 0xA7, 5, InData<u64>);
}

pub(super) fn init_in_first_kthread() {
    let major = super::MISC_MAJOR.get().unwrap().get();
    let id = DeviceId::new(major, MinorId::new(AGENT_CTL_MINOR));
    char::register(Arc::new(AgentCtlDevice { id })).unwrap();
}
