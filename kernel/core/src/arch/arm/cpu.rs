// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use ostd::{
    arch::cpu::context::{CpuException, UserContext},
    cpu::PinCurrentCpu,
    task::DisabledPreemptGuard,
    user::UserContextApi,
};

use crate::{
    cpu::{LinuxAbi, topology::CpuTopology},
    prelude::*,
    vm::{perms::VmPerms, vmar::PageFaultInfo},
};

impl LinuxAbi for UserContext {
    fn syscall_num(&self) -> usize {
        self.x8()
    }

    fn set_syscall_num(&mut self, num: usize) {
        self.set_x8(num);
    }

    fn syscall_ret(&self) -> usize {
        self.x0()
    }

    fn set_syscall_ret(&mut self, ret: usize) {
        self.set_x0(ret)
    }

    fn syscall_args(&self) -> [usize; 6] {
        [
            self.x0(),
            self.x1(),
            self.x2(),
            self.x3(),
            self.x4(),
            self.x5(),
        ]
    }
}

macro_rules! copy_gp_regs {
    ($regs: ident) => {
        copy_reg!(0, x0, $regs);
        copy_reg!(1, x1, $regs);
        copy_reg!(2, x2, $regs);
        copy_reg!(3, x3, $regs);
        copy_reg!(4, x4, $regs);
        copy_reg!(5, x5, $regs);
        copy_reg!(6, x6, $regs);
        copy_reg!(7, x7, $regs);
        copy_reg!(8, x8, $regs);
        copy_reg!(9, x9, $regs);
        copy_reg!(10, x10, $regs);
        copy_reg!(11, x11, $regs);
        copy_reg!(12, x12, $regs);
        copy_reg!(13, x13, $regs);
        copy_reg!(14, x14, $regs);
        copy_reg!(15, x15, $regs);
        copy_reg!(16, x16, $regs);
        copy_reg!(17, x17, $regs);
        copy_reg!(18, x18, $regs);
        copy_reg!(19, x19, $regs);
        copy_reg!(20, x20, $regs);
        copy_reg!(21, x21, $regs);
        copy_reg!(22, x22, $regs);
        copy_reg!(23, x23, $regs);
        copy_reg!(24, x24, $regs);
        copy_reg!(25, x25, $regs);
        copy_reg!(26, x26, $regs);
        copy_reg!(27, x27, $regs);
        copy_reg!(28, x28, $regs);
        copy_reg!(29, x29, $regs);
        copy_reg!(30, x30, $regs);
    };
}

/// Represents the context of a signal handler.
///
/// This contains the context saved before a signal handler is invoked; it will be restored by
/// `sys_rt_sigreturn`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/arm64/include/uapi/asm/sigcontext.h#L28-L37>
#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy, Debug, Pod)]
pub(crate) struct SigContext {
    fault_address: u64,
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    _pad: u64,
    /// The records of the FP/SIMD state and future extensions, each starting with a header of
    /// its magic and size, and terminated by a header of zeros.
    reserved: [u8; SIG_CONTEXT_RESERVED_SIZE],
}

const SIG_CONTEXT_RESERVED_SIZE: usize = 4096;

/// The size of the header of a record in [`SigContext::reserved`].
const RECORD_HEADER_SIZE: usize = 2 * size_of::<u32>();

// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/arm64/include/uapi/asm/sigcontext.h#L75-L94>
const FPSIMD_MAGIC: u32 = 0x46508001;
const ESR_MAGIC: u32 = 0x45535201;

impl Default for SigContext {
    fn default() -> Self {
        Self::new_zeroed()
    }
}

impl SigContext {
    /// Writes the FP/SIMD record, which must start with its header, followed by the terminator.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/arm64/kernel/signal.c#L1277-L1408>
    pub(crate) fn set_fpsimd_record(&mut self, record: &[u8]) {
        debug_assert!(record.len() + RECORD_HEADER_SIZE <= SIG_CONTEXT_RESERVED_SIZE);
        self.reserved.fill(0);
        self.reserved[..record.len()].copy_from_slice(record);
    }

    /// Returns the FP/SIMD record of `expected_size` bytes, after validating the records like
    /// Linux.
    ///
    /// Records that Asterinas never produces (SVE, SME, extra context, etc.) are rejected, like
    /// Linux does on systems that do not support them.
    ///
    /// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/arch/arm64/kernel/signal.c#L791-L1017>
    pub(crate) fn fpsimd_record(&self, expected_size: usize) -> Result<&[u8]> {
        let mut fpsimd = None;
        let mut offset = 0;
        loop {
            if SIG_CONTEXT_RESERVED_SIZE - offset < RECORD_HEADER_SIZE {
                return_errno_with_message!(Errno::EINVAL, "the signal frame has no terminator");
            }
            let header = &self.reserved[offset..offset + RECORD_HEADER_SIZE];
            let magic = u32::from_ne_bytes(header[..4].try_into().unwrap());
            let size = u32::from_ne_bytes(header[4..].try_into().unwrap()) as usize;
            if SIG_CONTEXT_RESERVED_SIZE - offset < size {
                return_errno_with_message!(Errno::EINVAL, "a signal frame record is too large");
            }

            match magic {
                0 if size == 0 => break,
                FPSIMD_MAGIC if fpsimd.is_none() => fpsimd = Some((offset, size)),
                ESR_MAGIC => {}
                _ => return_errno_with_message!(Errno::EINVAL, "invalid signal frame record"),
            }

            if size < RECORD_HEADER_SIZE {
                return_errno_with_message!(Errno::EINVAL, "a signal frame record is too small");
            }
            offset += size;
            if !offset.is_multiple_of(16) {
                return_errno_with_message!(Errno::EINVAL, "a signal frame record is misaligned");
            }
        }

        match fpsimd {
            Some((offset, size)) if size == expected_size => {
                Ok(&self.reserved[offset..offset + size])
            }
            _ => return_errno_with_message!(Errno::EINVAL, "invalid FP/SIMD signal frame record"),
        }
    }

    pub(crate) fn copy_user_regs_to(&self, dst: &mut UserContext) {
        macro_rules! copy_reg {
            ($idx: literal, $name: ident, $regs: ident) => {
                $regs.$name = self.regs[$idx] as usize;
            };
        }

        let gp_regs = dst.general_regs_mut();
        copy_gp_regs!(gp_regs);
        dst.set_stack_pointer(self.sp as usize);
        dst.set_instruction_pointer(self.pc as usize);
        dst.set_process_state(self.pstate as usize);
    }

    pub(crate) fn copy_user_regs_from(&mut self, src: &UserContext) {
        macro_rules! copy_reg {
            ($idx:literal, $name:ident, $regs: ident) => {
                self.regs[$idx] = $regs.$name as u64;
            };
        }

        let gp_regs = src.general_regs();
        copy_gp_regs!(gp_regs);
        self.sp = src.stack_pointer() as u64;
        self.pc = src.instruction_pointer() as u64;
        self.pstate = src.process_state() as u64;
    }
}

impl TryFrom<&CpuException> for PageFaultInfo {
    // [`Err`] indicates that the [`CpuException`] is not a page fault, with no
    // additional error information.
    type Error = ();

    fn try_from(value: &CpuException) -> Result<Self, ()> {
        let (addr, required_perms) = match value {
            CpuException::InstructionAbort { address } => (address, VmPerms::READ | VmPerms::EXEC),
            CpuException::DataAbort { is_write, address } => (
                address,
                if *is_write {
                    VmPerms::READ | VmPerms::WRITE
                } else {
                    VmPerms::READ
                },
            ),
            _ => return Err(()),
        };
        Ok(PageFaultInfo::new(*addr, required_perms))
    }
}

/// CPU information to be shown in `/proc/cpuinfo`.
///
/// Different CPUs may have different information, such as the core ID. Therefore, [`Self::new`]
/// should be called on every CPU.
//
// TODO: Implement CPU information retrieval on ARM platforms.
pub(crate) struct CpuInformation {
    processor: u32,
}

impl CpuInformation {
    /// Constructs the information for the current CPU.
    pub(crate) fn new(guard: &DisabledPreemptGuard) -> Self {
        Self {
            processor: guard.current_cpu().into(),
        }
    }
}

impl fmt::Display for CpuInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "processor\t: {}", self.processor)
    }
}

/// Probes the topology of the current CPU.
//
// TODO: Probe the real topology from the hardware or the firmware, as Linux does.
pub(crate) fn probe_topology(guard: &DisabledPreemptGuard) -> CpuTopology {
    CpuTopology::of_lone_core(guard.current_cpu())
}
