// SPDX-License-Identifier: MPL-2.0

//! The `/dev/agent_ctl` device.
//!
//! An agent shim inside the VM uses it to mark tool-call boundaries. To run a tool call,
//! the shim forks a child that begins a TCT and then executes the tool; after the tool
//! exits, the shim ends the TCT. See [`Tct`] for how processes are attributed to a TCT.
//!
//! Beginning and ending a TCT require `CAP_SYS_ADMIN`, and are refused for processes that
//! are already in a TCT, so a tool cannot leave its TCT or end it from the inside.

use device_id::{DeviceId, MinorId};

use crate::{
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

        // Checks that the caller may begin or end a TCT.
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
                let tct = Tct::end(end.id)?;
                end.nr_live_processes = tct.nr_live_processes() as u64;
                cmd.write(&end)?;
                Ok(0)
            }
            cmd @ TctGet => {
                cmd.write(&process.tct().map_or(0, |tct| tct.id()))?;
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

mod ioctl_defs {
    use super::TctEndArgs;
    use crate::{
        ioc,
        util::ioctl::{InOutData, OutData},
    };

    // TCT IDs start from 1; `AGENT_CTL_TCT_GET` returns 0 outside a TCT.
    pub(super) type TctBegin = ioc!(AGENT_CTL_TCT_BEGIN, 0xA7, 1, OutData<u64>);
    pub(super) type TctEnd   = ioc!(AGENT_CTL_TCT_END,   0xA7, 2, InOutData<TctEndArgs>);
    pub(super) type TctGet   = ioc!(AGENT_CTL_TCT_GET,   0xA7, 3, OutData<u64>);
}

pub(super) fn init_in_first_kthread() {
    let major = super::MISC_MAJOR.get().unwrap().get();
    let id = DeviceId::new(major, MinorId::new(AGENT_CTL_MINOR));
    char::register(Arc::new(AgentCtlDevice { id })).unwrap();
}
