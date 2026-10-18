// SPDX-License-Identifier: MPL-2.0

use bitflags::bitflags;

use super::{
    c_types::sigaction_t,
    constants::*,
    sig_mask::{SigMask, SigSet},
    sig_num::SigNum,
};
use crate::prelude::*;

/// A signal action.
///
/// Like `struct k_sigaction` in Linux, the flags, the mask, and the restorer are kept for every
/// handler, including `SIG_DFL` and `SIG_IGN`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L4383-L4441>
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SigAction {
    pub(crate) handler: SigHandler,
    pub(crate) flags: SigActionFlags,
    pub(crate) restorer_addr: Vaddr,
    pub(crate) mask: SigMask,
}

/// The handler of a signal action.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum SigHandler {
    /// The default action.
    #[default]
    Dfl,
    /// Ignoring the signal.
    Ign,
    /// A user-given handler at the address.
    User(Vaddr),
}

impl Default for SigAction {
    fn default() -> Self {
        Self {
            handler: SigHandler::Dfl,
            flags: SigActionFlags::empty(),
            restorer_addr: 0,
            mask: SigMask::new_empty(),
        }
    }
}

impl From<sigaction_t> for SigAction {
    fn from(input: sigaction_t) -> Self {
        let handler = match input.handler_ptr {
            SIG_DFL => SigHandler::Dfl,
            SIG_IGN => SigHandler::Ign,
            handler_addr => SigHandler::User(handler_addr),
        };

        Self {
            handler,
            // Unknown flags are cleared so that user space can detect unsupported flags.
            flags: SigActionFlags::from_bits_truncate(input.flags),
            restorer_addr: input.restorer_ptr,
            mask: SigSet::from(input.mask) - SIGKILL - SIGSTOP,
        }
    }
}

impl SigAction {
    pub(crate) fn as_c_type(&self) -> sigaction_t {
        let handler_ptr = match self.handler {
            SigHandler::Dfl => SIG_DFL,
            SigHandler::Ign => SIG_IGN,
            SigHandler::User(handler_addr) => handler_addr,
        };

        sigaction_t {
            handler_ptr,
            flags: self.flags.as_u32(),
            restorer_ptr: self.restorer_addr,
            mask: self.mask.into(),
            ..Default::default()
        }
    }

    /// Returns whether signals will be ignored.
    ///
    /// Signals will be ignored because either
    ///  * the signal action is explicitly set to ignore the signals, or
    ///  * the signal action is default and the default action is to ignore the signals.
    pub(crate) fn will_ignore(&self, signum: SigNum) -> bool {
        match self.handler {
            SigHandler::Dfl => {
                let default_action = SigDefaultAction::from_signum(signum);
                matches!(default_action, SigDefaultAction::Ign)
            }
            SigHandler::Ign => true,
            SigHandler::User(_) => false,
        }
    }
}

bitflags! {
    pub(crate) struct SigActionFlags: u32 {
        const SA_NOCLDSTOP  = 1;
        const SA_NOCLDWAIT  = 2;
        const SA_SIGINFO    = 4;
        const SA_EXPOSE_TAGBITS = 0x00000800;
        const SA_ONSTACK    = 0x08000000;
        const SA_RESTART    = 0x10000000;
        const SA_NODEFER    = 0x40000000;
        const SA_RESETHAND  = 0x80000000;
        const SA_RESTORER   = 0x04000000;
    }
}

impl TryFrom<u32> for SigActionFlags {
    type Error = Error;

    fn try_from(bits: u32) -> Result<Self> {
        let flags = SigActionFlags::from_bits(bits)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid sig action flag"))?;
        Ok(flags)
    }
}

impl SigActionFlags {
    pub(crate) fn as_u32(&self) -> u32 {
        self.bits()
    }
}

/// The default action to signals
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SigDefaultAction {
    Term, // Default action is to terminate the process.
    Ign,  // Default action is to ignore the signal.
    Core, // Default action is to terminate the process and dump core (see core(5)).
    Stop, // Default action is to stop the process.
    Cont, // Default action is to continue the process if it is currently stopped.
}

impl SigDefaultAction {
    pub(crate) fn from_signum(num: SigNum) -> SigDefaultAction {
        match num {
            SIGABRT | // = SIGIOT
            SIGBUS  |
            SIGFPE  |
            SIGILL  |
            SIGQUIT |
            SIGSEGV |
            SIGSYS  | // = SIGUNUSED
            SIGTRAP |
            SIGXCPU |
            SIGXFSZ
                => SigDefaultAction::Core,
            SIGCHLD |
            SIGURG  |
            SIGWINCH
                => SigDefaultAction::Ign,
            SIGCONT
                => SigDefaultAction::Cont,
            SIGSTOP |
            SIGTSTP |
            SIGTTIN |
            SIGTTOU
                => SigDefaultAction::Stop,
            _
                => SigDefaultAction::Term,
        }
    }
}
