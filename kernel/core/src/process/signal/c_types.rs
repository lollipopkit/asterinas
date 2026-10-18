// SPDX-License-Identifier: MPL-2.0

#![expect(dead_code)]
#![expect(non_camel_case_types)]

use inherit_methods_macro::inherit_methods;
use ostd::arch::cpu::context::UserContext;

use super::{constants::*, sig_num::SigNum};
use crate::{
    arch::cpu::SigContext,
    prelude::*,
    process::{Pid, Uid},
    time::clock_t,
};

pub(crate) type sigset_t = u64;

#[padding_struct]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct sigaction_t {
    pub handler_ptr: Vaddr,
    pub flags: u32,
    pub restorer_ptr: Vaddr,
    pub mask: sigset_t,
}

/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/uapi/asm-generic/siginfo.h#L116-L139>
#[padding_struct]
#[repr(C)]
#[derive(Clone, Copy, Default, Pod)]
pub(crate) struct siginfo_t {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    // On 64-bit architectures, there is a 4-byte padding here, so the offset of `siginfo_fields`
    // is `0x10`.
    siginfo_fields: siginfo_fields_t,
}

ostd::const_assert!(size_of::<siginfo_t>() == 128);

/// The size of the meaningful part of `siginfo_t` (i.e., Linux's `struct kernel_siginfo`).
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/linux/signal_types.h#L12-L14>
const KERNEL_SIGINFO_SIZE: usize = size_of::<i32>() * 4 + size_of::<siginfo_sigfault_t>();

impl siginfo_t {
    pub(crate) fn new(num: SigNum, code: i32) -> Self {
        siginfo_t {
            si_signo: num.as_u8() as i32,
            si_errno: 0,
            si_code: code,
            siginfo_fields: siginfo_fields_t::zero_fields(),
            ..Default::default()
        }
    }

    /// Reads a `siginfo_t` from the user space, like Linux's `copy_siginfo_from_user`.
    ///
    /// If `signo` is not `None`, it overrides `si_signo` before the layout is checked.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L3591-L3628>
    pub(crate) fn read_from_user(addr: Vaddr, signo: Option<i32>, ctx: &Context) -> Result<Self> {
        let user_space = ctx.user_space();

        let mut info = Self::new_zeroed();
        user_space
            .reader(addr, KERNEL_SIGINFO_SIZE)?
            .read_fallible(&mut VmWriter::from(
                &mut info.as_mut_bytes()[..KERNEL_SIGINFO_SIZE],
            ))?;
        if let Some(signo) = signo {
            info.si_signo = signo;
        }

        // An unknown `si_code` may use the trailing bytes, which must be zero so that they can
        // be returned to the user space exactly.
        if !info.is_layout_known() {
            let mut reader = user_space.reader(
                addr + KERNEL_SIGINFO_SIZE,
                size_of::<Self>() - KERNEL_SIGINFO_SIZE,
            )?;
            while reader.has_remain() {
                if reader.read_val::<u64>()? != 0 {
                    return_errno_with_message!(
                        Errno::E2BIG,
                        "the unknown `siginfo_t` layout uses the trailing bytes"
                    );
                }
            }
        }

        Ok(info)
    }

    /// Returns the layout of the union fields.
    pub(crate) fn layout(&self) -> SigInfoLayout {
        SigInfoLayout::new(self.si_signo, self.si_code)
    }

    /// Returns whether the layout of the union fields is known.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L3517-L3534>
    fn is_layout_known(&self) -> bool {
        let code = self.si_code;
        if code == SI_KERNEL {
            true
        } else if code > SI_USER {
            match sig_sicodes(self.si_signo) {
                Some((limit, _)) => code <= limit,
                None => code <= NSIGPOLL,
            }
        } else {
            code >= SI_DETHREAD || code == SI_ASYNCNL
        }
    }

    pub(crate) fn set_si_addr(&mut self, si_addr: Vaddr) {
        self.siginfo_fields.sigfault_mut().addr = si_addr;
    }

    pub(crate) fn set_pid_uid(&mut self, pid: Pid, uid: Uid) {
        let pid_uid = {
            let pid_uid = siginfo_piduid_t { pid, uid };
            siginfo_common_first_t::new_piduid(pid_uid)
        };

        self.siginfo_fields.common_mut().first = pid_uid;
    }

    /// Sets the TID and the real UID of the current thread, like the ptrace-stop `siginfo_t`.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L2595-L2596>
    pub(crate) fn set_pid_uid_by(&mut self, ctx: &Context) {
        self.set_pid_uid(
            ctx.posix_thread.tid(),
            ctx.posix_thread.credentials().ruid(),
        );
    }

    pub(crate) fn set_timer(&mut self, timer_id: i32, overrun: i32) {
        let timer = siginfo_timer_t {
            timerid: timer_id,
            overrun,
        };
        self.siginfo_fields.common_mut().first = siginfo_common_first_t::new_timer(timer);
    }

    pub(crate) fn set_value(&mut self, value: sigval_t) {
        self.siginfo_fields.common_mut().second = siginfo_common_second_t::new_value(value);
    }

    pub(crate) fn set_status(&mut self, status: i32) {
        self.siginfo_fields
            .common_mut()
            .second
            .sigchild_mut()
            .status = status;
    }

    pub(crate) fn set_utime_stime(&mut self, utime: clock_t, stime: clock_t) {
        let sigchild = self.siginfo_fields.common_mut().second.sigchild_mut();
        sigchild.utime = utime;
        sigchild.stime = stime;
    }

    pub(crate) fn pid(&self) -> Pid {
        self.siginfo_fields.common().first.piduid().pid
    }

    pub(crate) fn uid(&self) -> Uid {
        self.siginfo_fields.common().first.piduid().uid
    }

    pub(crate) fn timer_id(&self) -> i32 {
        self.siginfo_fields.common().first.timer().timerid
    }

    pub(crate) fn overrun(&self) -> i32 {
        self.siginfo_fields.common().first.timer().overrun
    }

    pub(crate) fn value(&self) -> sigval_t {
        *self.siginfo_fields.common().second.value()
    }

    pub(crate) fn status(&self) -> i32 {
        self.siginfo_fields.common().second.sigchild().status
    }

    pub(crate) fn utime(&self) -> clock_t {
        self.siginfo_fields.common().second.sigchild().utime
    }

    pub(crate) fn stime(&self) -> clock_t {
        self.siginfo_fields.common().second.sigchild().stime
    }

    pub(crate) fn si_addr(&self) -> Vaddr {
        self.siginfo_fields.sigfault().addr
    }

    pub(crate) fn trapno(&self) -> i32 {
        *self.siginfo_fields.sigfault().extra.trapno()
    }

    pub(crate) fn addr_lsb(&self) -> i16 {
        *self.siginfo_fields.sigfault().extra.addr_lsb()
    }

    pub(crate) fn band(&self) -> i64 {
        self.siginfo_fields.sigpoll().band
    }

    pub(crate) fn fd(&self) -> i32 {
        self.siginfo_fields.sigpoll().fd
    }

    pub(crate) fn call_addr(&self) -> Vaddr {
        self.siginfo_fields.sigsys().call_addr
    }

    pub(crate) fn syscall(&self) -> i32 {
        self.siginfo_fields.sigsys().syscall
    }

    pub(crate) fn arch(&self) -> u32 {
        self.siginfo_fields.sigsys().arch
    }
}

/// The layout of the union fields in `siginfo_t`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/linux/signal.h#L39-L52>
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SigInfoLayout {
    Kill,
    Timer,
    Poll,
    Fault,
    FaultTrapno,
    FaultMceerr,
    FaultBnderr,
    FaultPkuerr,
    FaultPerfEvent,
    Chld,
    Rt,
    Sys,
}

impl SigInfoLayout {
    /// Determines the layout from the signal number and the signal code.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L3536-L3574>
    pub(crate) fn new(signo: i32, code: i32) -> Self {
        if code > SI_USER && code < SI_KERNEL {
            if let Some((limit, layout)) = sig_sicodes(signo)
                && code <= limit
            {
                // `FaultTrapno` is only used on Alpha and SPARC.
                match (signo, code) {
                    (SIGBUS_NUM, BUS_MCEERR_AR..=BUS_MCEERR_AO) => Self::FaultMceerr,
                    (SIGSEGV_NUM, SEGV_BNDERR) => Self::FaultBnderr,
                    (SIGSEGV_NUM, SEGV_PKUERR) => Self::FaultPkuerr,
                    (SIGTRAP_NUM, TRAP_PERF) => Self::FaultPerfEvent,
                    _ => layout,
                }
            } else if code <= NSIGPOLL {
                Self::Poll
            } else {
                Self::Kill
            }
        } else if code == SI_TIMER {
            Self::Timer
        } else if code == SI_SIGIO {
            Self::Poll
        } else if code < 0 {
            Self::Rt
        } else {
            Self::Kill
        }
    }
}

const SIGBUS_NUM: i32 = SIGBUS.as_u8() as i32;
const SIGSEGV_NUM: i32 = SIGSEGV.as_u8() as i32;
const SIGTRAP_NUM: i32 = SIGTRAP.as_u8() as i32;

/// Returns the number of signal-specific codes and the default layout of the signal.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/kernel/signal.c#L3501-L3515>
fn sig_sicodes(signo: i32) -> Option<(i32, SigInfoLayout)> {
    let num = SigNum::try_from_raw(signo as u64).ok().flatten()?;
    let sicodes = match num {
        SIGILL => (NSIGILL, SigInfoLayout::Fault),
        SIGFPE => (NSIGFPE, SigInfoLayout::Fault),
        SIGSEGV => (NSIGSEGV, SigInfoLayout::Fault),
        SIGBUS => (NSIGBUS, SigInfoLayout::Fault),
        SIGTRAP => (NSIGTRAP, SigInfoLayout::Fault),
        SIGCHLD => (NSIGCHLD, SigInfoLayout::Chld),
        SIGPOLL => (NSIGPOLL, SigInfoLayout::Poll),
        SIGSYS => (NSIGSYS, SigInfoLayout::Sys),
        _ => return None,
    };
    Some(sicodes)
}

/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/uapi/asm-generic/siginfo.h#L37-L114>
#[pod_union]
#[repr(C)]
#[derive(Clone, Copy)]
union siginfo_fields_t {
    bytes: [u8; 128 - size_of::<i32>() * 4],
    common: siginfo_common_t,
    sigfault: siginfo_sigfault_t,
    sigpoll: siginfo_sigpoll_t,
    sigsys: siginfo_sigsys_t,
}

impl Default for siginfo_fields_t {
    fn default() -> Self {
        Self::new_zeroed()
    }
}

impl siginfo_fields_t {
    fn zero_fields() -> Self {
        Self::new_zeroed()
    }
}

/// The `_kill`, `_timer`, `_rt`, and `_sigchld` fields, which share the same prefix.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct siginfo_common_t {
    first: siginfo_common_first_t,
    second: siginfo_common_second_t,
}

#[pod_union]
#[repr(C)]
#[derive(Clone, Copy)]
union siginfo_common_first_t {
    piduid: siginfo_piduid_t,
    timer: siginfo_timer_t,
}

#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct siginfo_piduid_t {
    pid: Pid,
    uid: Uid,
}

#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct siginfo_timer_t {
    timerid: i32,
    overrun: i32,
}

#[pod_union]
#[repr(C)]
#[derive(Clone, Copy)]
union siginfo_common_second_t {
    value: sigval_t,
    sigchild: siginfo_sigchild_t,
}

#[pod_union]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union sigval_t {
    sigval_int: i32,
    sigval_ptr: Vaddr, //*mut c_void
}

impl sigval_t {
    pub(crate) fn read_int(&self) -> i32 {
        *self.sigval_int()
    }

    pub(crate) fn read_ptr(&self) -> Vaddr {
        *self.sigval_ptr()
    }
}

/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/uapi/asm-generic/siginfo.h#L59-L66>
#[padding_struct]
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct siginfo_sigchild_t {
    status: i32,
    utime: clock_t,
    stime: clock_t,
}

/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/uapi/asm-generic/siginfo.h#L68-L100>
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct siginfo_sigfault_t {
    addr: Vaddr, //*const c_void
    extra: siginfo_sigfault_extra_t,
}

#[pod_union]
#[repr(C)]
#[derive(Clone, Copy)]
union siginfo_sigfault_extra_t {
    trapno: i32,
    addr_lsb: i16,
    addr_bnd: siginfo_addr_bnd_t,
    addr_pkey: siginfo_addr_pkey_t,
    perf: siginfo_perf_t,
}

/// The padding before the `_addr_bnd` and `_addr_pkey` fields, which is `__ADDR_BND_PKEY_PAD`.
const ADDR_BND_PKEY_PAD: usize = align_of::<Vaddr>();

#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct siginfo_addr_bnd_t {
    _dummy_bnd: [u8; ADDR_BND_PKEY_PAD],
    lower: Vaddr, // *const c_void
    upper: Vaddr, // *const c_void
}

#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct siginfo_addr_pkey_t {
    _dummy_pkey: [u8; ADDR_BND_PKEY_PAD],
    pkey: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct siginfo_perf_t {
    data: usize,
    type_: u32,
    flags: u32,
}

/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/uapi/asm-generic/siginfo.h#L102-L106>
#[padding_struct]
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct siginfo_sigpoll_t {
    band: i64,
    fd: i32,
}

/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/include/uapi/asm-generic/siginfo.h#L108-L113>
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct siginfo_sigsys_t {
    call_addr: Vaddr, // *const c_void
    syscall: i32,
    arch: u32,
}

/// Reference: <https://elixir.bootlin.com/linux/v6.15.7/source/include/uapi/asm-generic/ucontext.h#L5>
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct ucontext_t {
    pub uc_flags: u64,
    pub uc_link: Vaddr, // *mut ucontext_t
    pub uc_stack: stack_t,
    pub uc_mcontext: mcontext_t,
    pub uc_sigmask: sigset_t,
}

/// Reference: <https://elixir.bootlin.com/linux/v6.15.7/source/arch/riscv/include/uapi/asm/ucontext.h>
/// Reference: <https://elixir.bootlin.com/linux/v6.15.7/source/arch/loongarch/include/uapi/asm/ucontext.h>
/// Reference: <https://elixir.bootlin.com/linux/v6.15.7/source/arch/arm64/include/uapi/asm/ucontext.h>
#[cfg(any(
    target_arch = "riscv64",
    target_arch = "loongarch64",
    target_arch = "aarch64"
))]
#[padding_struct]
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(crate) struct ucontext_t {
    pub uc_flags: u64,
    pub uc_link: Vaddr, // *mut ucontext_t
    pub uc_stack: stack_t,
    pub uc_sigmask: sigset_t,
    pub __unused: [u8; 120],
    pub uc_mcontext: mcontext_t,
}

// FIXME: Currently Rust generates array impls for every size up to 32 manually
// and there is ongoing work on refactoring with const generics. We can just
// derive the `Default` implementation once that is done.
//
// See <https://github.com/rust-lang/rust/issues/61415>.
#[cfg(any(
    target_arch = "riscv64",
    target_arch = "loongarch64",
    target_arch = "aarch64"
))]
impl Default for ucontext_t {
    fn default() -> Self {
        Self {
            uc_flags: 0,
            __pad1: [0; _],
            uc_link: Default::default(),
            __pad2: [0; _],
            uc_stack: Default::default(),
            __pad3: [0; _],
            uc_sigmask: Default::default(),
            __pad4: [0; _],
            __unused: [0; 120],
            __pad5: [0; _],
            uc_mcontext: Default::default(),
            __pad6: [0; _],
        }
    }
}

pub(crate) type stack_t = sigaltstack_t;

#[padding_struct]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct sigaltstack_t {
    pub ss_sp: Vaddr, // *mut c_void
    pub ss_flags: i32,
    pub ss_size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct mcontext_t {
    inner: SigContext,
}

#[inherit_methods(from = "self.inner")]
impl mcontext_t {
    pub(crate) fn copy_user_regs_to(&self, context: &mut UserContext);
    pub(crate) fn copy_user_regs_from(&mut self, context: &UserContext);
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn fpu_context_addr(&self) -> Vaddr;
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn set_fpu_context_addr(&mut self, addr: Vaddr);
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn set_fpsimd_record(&mut self, record: &[u8]);
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn fpsimd_record(&self, expected_size: usize) -> Result<&[u8]>;
}

#[repr(C)]
#[derive(Clone, Copy, Pod)]
pub(crate) struct _sigev_thread {
    pub function: Vaddr,
    pub attribute: Vaddr,
}

const SIGEV_MAX_SIZE: usize = 64;
/// The total size of the fields `sigev_value`, `sigev_signo` and `sigev_notify`.
const SIGEV_PREAMBLE_SIZE: usize = size_of::<i32>() * 2 + size_of::<sigval_t>();
const SIGEV_PAD_SIZE: usize = (SIGEV_MAX_SIZE - SIGEV_PREAMBLE_SIZE) / size_of::<i32>();

#[pod_union]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union _sigev_un {
    pub _pad: [i32; SIGEV_PAD_SIZE],
    pub _tid: i32,
    pub _sigev_thread: _sigev_thread,
}

impl _sigev_un {
    pub(crate) fn read_tid(&self) -> i32 {
        *self._tid()
    }

    pub(crate) fn read_function(&self) -> Vaddr {
        self._sigev_thread().function
    }

    pub(crate) fn read_attribute(&self) -> Vaddr {
        self._sigev_thread().attribute
    }
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, TryFromInt)]
pub(crate) enum SigNotify {
    SIGEV_SIGNAL = 0,
    SIGEV_NONE = 1,
    SIGEV_THREAD = 2,
    SIGEV_THREAD_ID = 4,
}

#[repr(C)]
#[derive(Clone, Copy, Pod)]
pub(crate) struct sigevent_t {
    pub sigev_value: sigval_t,
    pub sigev_signo: i32,
    pub sigev_notify: i32,
    pub sigev_un: _sigev_un,
}
