// SPDX-License-Identifier: MPL-2.0

// Failures to set up or restore a signal frame raise `SIGSEGV`.
//
// If the kernel fails to push the frame of a signal, it forces `SIGSEGV`
// instead, which can still be handled on an alternate signal stack. If the
// failing signal is `SIGSEGV` itself, its handler is reset to `SIG_DFL`. An
// invalid frame passed to `rt_sigreturn` also raises `SIGSEGV`.

#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#include "../../common/test.h"

#define PAGE_SIZE 4096
#define ALT_STACK_SIZE (SIGSTKSZ + 65536)
#define DEFAULT_MXCSR 0x1f80
// Round toward negative infinity.
#define CUSTOM_MXCSR 0x3f80

static char *bad_stack;
static char *alt_stack;

static sigjmp_buf jmp_env;
static volatile int sigusr1_count;
static volatile int sigsegv_count;
static volatile int sigsegv_code;
static volatile greg_t sigsegv_rip;
static volatile greg_t sigsegv_rsp;
static volatile greg_t sigsegv_rax;
static volatile uint32_t sigsegv_mxcsr;
static volatile int sigsegv_on_alt_stack;
static sigset_t sigsegv_saved_mask;
static sigset_t sigsegv_cur_mask;

// The middle of a `PROT_NONE` region, so that neither pushing a signal frame
// below it nor reading a signal frame above it succeeds.
#define BAD_STACK_SIZE (PAGE_SIZE * 8)
#define BAD_SP ((void *)(bad_stack + BAD_STACK_SIZE / 2))

// Sends `sig` to the current thread while the stack pointer is `sp`.
static void tkill_on_stack(void *sp, int sig)
{
	long tid = syscall(SYS_gettid);
	long nr = SYS_tkill;

	asm volatile("mov %%rsp, %%r12\n\t"
		     "mov %[sp], %%rsp\n\t"
		     "syscall\n\t"
		     "mov %%r12, %%rsp"
		     : "+a"(nr)
		     : "D"(tid), "S"(sig), [sp] "r"(sp)
		     : "rcx", "r11", "r12", "memory");
}

// Waits for a signal with `rt_sigsuspend` while the stack pointer is `sp`.
static void sigsuspend_on_stack(void *sp, const sigset_t *mask)
{
	long nr = SYS_rt_sigsuspend;

	asm volatile("mov %%rsp, %%r12\n\t"
		     "mov %[sp], %%rsp\n\t"
		     "syscall\n\t"
		     "mov %%r12, %%rsp"
		     : "+a"(nr)
		     : "D"(mask), "S"(8), [sp] "r"(sp)
		     : "rcx", "r11", "r12", "memory");
}

// Calls `rt_sigreturn` with the stack pointer `sp` and the MXCSR `mxcsr`.
static void sigreturn_on_stack(void *sp, uint32_t mxcsr)
{
	long nr = SYS_rt_sigreturn;

	asm volatile("ldmxcsr %[mxcsr]\n\t"
		     "mov %%rsp, %%r12\n\t"
		     "mov %[sp], %%rsp\n\t"
		     "syscall\n\t"
		     "mov %%r12, %%rsp"
		     : "+a"(nr)
		     : [sp] "r"(sp), [mxcsr] "m"(mxcsr)
		     : "rcx", "r11", "r12", "memory");
}

static void sigusr1_handler(int sig)
{
	(void)sig;
	sigusr1_count++;
}

static void sigsegv_handler(int sig, siginfo_t *info, void *ctx)
{
	ucontext_t *uc = ctx;
	char *sp = (char *)&uc;

	(void)sig;
	sigsegv_count++;
	sigsegv_code = info->si_code;
	sigsegv_rip = uc->uc_mcontext.gregs[REG_RIP];
	sigsegv_rsp = uc->uc_mcontext.gregs[REG_RSP];
	sigsegv_rax = uc->uc_mcontext.gregs[REG_RAX];
	sigsegv_mxcsr = uc->uc_mcontext.fpregs->mxcsr;
	sigsegv_on_alt_stack = sp >= alt_stack &&
			       sp < alt_stack + ALT_STACK_SIZE;
	sigsegv_saved_mask = uc->uc_sigmask;
	sigprocmask(SIG_BLOCK, NULL, &sigsegv_cur_mask);

	siglongjmp(jmp_env, 1);
}

static void reset_records(void)
{
	sigusr1_count = 0;
	sigsegv_count = 0;
	sigsegv_code = 0;
	sigsegv_rip = 0;
	sigsegv_rsp = 0;
	sigsegv_rax = -1;
	sigsegv_mxcsr = 0;
	sigsegv_on_alt_stack = 0;
	sigemptyset(&sigsegv_saved_mask);
	sigemptyset(&sigsegv_cur_mask);
}

static int install_handler(int sig, void *handler, int flags)
{
	struct sigaction sa = { 0 };

	if (handler == SIG_DFL || handler == SIG_IGN || !(flags & SA_SIGINFO))
		sa.sa_handler = handler;
	else
		sa.sa_sigaction = handler;
	sa.sa_flags = flags;
	return sigaction(sig, &sa, NULL);
}

static int sigsegv_handler_is(void *handler)
{
	struct sigaction sa;

	if (sigaction(SIGSEGV, NULL, &sa) < 0)
		return 0;
	return (void *)sa.sa_handler == handler;
}

FN_SETUP(init)
{
	stack_t ss;

	bad_stack = CHECK_WITH(mmap(NULL, BAD_STACK_SIZE, PROT_NONE,
				    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
			       _ret != MAP_FAILED);
	alt_stack =
		CHECK_WITH(mmap(NULL, ALT_STACK_SIZE, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
			   _ret != MAP_FAILED);

	ss.ss_sp = alt_stack;
	ss.ss_size = ALT_STACK_SIZE;
	ss.ss_flags = 0;
	CHECK(sigaltstack(&ss, NULL));
}
END_SETUP()

FN_TEST(setup_fault_runs_sigsegv_handler_on_alt_stack)
{
	sigset_t pending;

	reset_records();
	TEST_SUCC(install_handler(SIGUSR1, sigusr1_handler, 0));
	TEST_SUCC(install_handler(SIGSEGV, sigsegv_handler,
				  SA_SIGINFO | SA_ONSTACK | SA_NODEFER));

	if (sigsetjmp(jmp_env, 1) == 0)
		tkill_on_stack(BAD_SP, SIGUSR1);

	TEST_RES(sigsegv_count, _ret == 1 && sigusr1_count == 0);
	TEST_RES(sigsegv_code, _ret == SI_KERNEL);
	TEST_RES(sigsegv_on_alt_stack, _ret);
	TEST_RES(sigsegv_rsp, _ret == (greg_t)BAD_SP);
	// The frame of the failed signal is not delivered, so the signal is not
	// blocked.
	TEST_RES(sigismember(&sigsegv_saved_mask, SIGUSR1), _ret == 0);
	TEST_RES(sigismember(&sigsegv_cur_mask, SIGUSR1), _ret == 0);
	// The handler of `SIGSEGV` is kept.
	TEST_RES(sigsegv_handler_is(sigsegv_handler), _ret);
	// The failed signal is consumed.
	TEST_SUCC(sigpending(&pending));
	TEST_RES(sigismember(&pending, SIGUSR1), _ret == 0);

	TEST_SUCC(install_handler(SIGUSR1, SIG_DFL, 0));
	TEST_SUCC(install_handler(SIGSEGV, SIG_DFL, 0));
}
END_TEST()

FN_TEST(setup_fault_keeps_saved_mask)
{
	sigset_t mask, old_mask, wait_mask;

	reset_records();
	TEST_SUCC(install_handler(SIGUSR1, sigusr1_handler, 0));
	TEST_SUCC(install_handler(SIGSEGV, sigsegv_handler,
				  SA_SIGINFO | SA_ONSTACK | SA_NODEFER));

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	TEST_SUCC(sigprocmask(SIG_BLOCK, &mask, &old_mask));
	TEST_SUCC(raise(SIGUSR1));

	// `SIGUSR1` is delivered with the temporary mask of `rt_sigsuspend`.
	// The frame of the forced `SIGSEGV` must save the original mask.
	sigemptyset(&wait_mask);
	if (sigsetjmp(jmp_env, 1) == 0)
		sigsuspend_on_stack(BAD_SP, &wait_mask);

	TEST_RES(sigsegv_count, _ret == 1 && sigusr1_count == 0);
	TEST_RES(sigsegv_rsp, _ret == (greg_t)BAD_SP);
	TEST_RES(sigismember(&sigsegv_saved_mask, SIGUSR1), _ret == 1);

	TEST_SUCC(sigprocmask(SIG_SETMASK, &old_mask, NULL));
	TEST_SUCC(install_handler(SIGUSR1, SIG_DFL, 0));
	TEST_SUCC(install_handler(SIGSEGV, SIG_DFL, 0));
}
END_TEST()

static void setup_fault_of_sigsegv(void)
{
	// The forced `SIGSEGV` would fail again without an alternate stack.
	install_handler(SIGSEGV, sigsegv_handler, SA_SIGINFO);
	tkill_on_stack(BAD_SP, SIGSEGV);
}

static void setup_fault_with_sigsegv_blocked(void)
{
	sigset_t mask;

	install_handler(SIGUSR1, sigusr1_handler, 0);
	install_handler(SIGSEGV, sigsegv_handler, SA_SIGINFO | SA_ONSTACK);
	sigemptyset(&mask);
	sigaddset(&mask, SIGSEGV);
	sigprocmask(SIG_BLOCK, &mask, NULL);
	tkill_on_stack(BAD_SP, SIGUSR1);
}

static void setup_fault_with_sigsegv_ignored(void)
{
	install_handler(SIGUSR1, sigusr1_handler, 0);
	install_handler(SIGSEGV, SIG_IGN, 0);
	tkill_on_stack(BAD_SP, SIGUSR1);
}

static void sigreturn_with_bad_stack(void)
{
	sigreturn_on_stack(BAD_SP, DEFAULT_MXCSR);
}

#define TEST_CHILD_KILLED_BY_SIGSEGV(func)             \
	pid = TEST_SUCC(fork());                       \
	if (pid == 0) {                                \
		func();                                \
		_exit(EXIT_FAILURE);                   \
	}                                              \
	TEST_RES(waitpid(pid, &status, 0),             \
		 _ret == pid && WIFSIGNALED(status) && \
			 WTERMSIG(status) == SIGSEGV)

FN_TEST(setup_fault_forces_sigsegv)
{
	pid_t pid;
	int status;

	// If the failed signal is `SIGSEGV`, its handler is reset to `SIG_DFL`.
	TEST_CHILD_KILLED_BY_SIGSEGV(setup_fault_of_sigsegv);
	// A blocked or ignored `SIGSEGV` is still delivered.
	TEST_CHILD_KILLED_BY_SIGSEGV(setup_fault_with_sigsegv_blocked);
	TEST_CHILD_KILLED_BY_SIGSEGV(setup_fault_with_sigsegv_ignored);
	// An unreadable frame of `rt_sigreturn` raises `SIGSEGV`.
	TEST_CHILD_KILLED_BY_SIGSEGV(sigreturn_with_bad_stack);
}
END_TEST()

FN_TEST(sigreturn_with_unreadable_frame)
{
	sigset_t mask, old_mask;

	reset_records();
	TEST_SUCC(install_handler(SIGSEGV, sigsegv_handler,
				  SA_SIGINFO | SA_ONSTACK | SA_NODEFER));

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR2);
	TEST_SUCC(sigprocmask(SIG_BLOCK, &mask, &old_mask));

	if (sigsetjmp(jmp_env, 1) == 0)
		sigreturn_on_stack(BAD_SP, DEFAULT_MXCSR);

	TEST_RES(sigsegv_count, _ret == 1);
	TEST_RES(sigsegv_code, _ret == SI_KERNEL);
	TEST_RES(sigsegv_on_alt_stack, _ret);
	// No state is restored, and `rt_sigreturn` returns zero.
	TEST_RES(sigsegv_rsp, _ret == (greg_t)BAD_SP);
	TEST_RES(sigsegv_rax, _ret == 0);
	TEST_RES(sigismember(&sigsegv_saved_mask, SIGUSR2), _ret == 1);

	TEST_SUCC(sigprocmask(SIG_SETMASK, &old_mask, NULL));
	TEST_SUCC(install_handler(SIGSEGV, SIG_DFL, 0));
}
END_TEST()

// A signal frame on the stack, preceded by the return address slot.
static struct {
	uint64_t pretcode;
	ucontext_t uc;
	siginfo_t info;
} __attribute__((aligned(64))) frame;

FN_TEST(sigreturn_with_bad_fpu_context)
{
	sigset_t mask, old_mask;
	stack_t ss;

	reset_records();
	TEST_SUCC(install_handler(SIGSEGV, sigsegv_handler,
				  SA_SIGINFO | SA_ONSTACK | SA_NODEFER));

	sigemptyset(&mask);
	TEST_SUCC(sigprocmask(SIG_SETMASK, &mask, &old_mask));
	TEST_SUCC(sigaltstack(NULL, &ss));

	memset(&frame, 0, sizeof(frame));
	TEST_SUCC(getcontext(&frame.uc));
	frame.uc.uc_flags = 0;
	frame.uc.uc_link = NULL;
	frame.uc.uc_stack = ss;
	frame.uc.uc_mcontext.gregs[REG_RIP] = 0x1234560;
	frame.uc.uc_mcontext.gregs[REG_RSP] = 0x7654320;
	frame.uc.uc_mcontext.gregs[REG_RAX] = 42;
	frame.uc.uc_mcontext.fpregs = (fpregset_t)bad_stack;
	sigemptyset(&frame.uc.uc_sigmask);
	sigaddset(&frame.uc.uc_sigmask, SIGUSR2);

	if (sigsetjmp(jmp_env, 1) == 0)
		sigreturn_on_stack(&frame.uc, CUSTOM_MXCSR);
	asm volatile("ldmxcsr %0" : : "m"((uint32_t){ DEFAULT_MXCSR }));

	TEST_RES(sigsegv_count, _ret == 1);
	TEST_RES(sigsegv_code, _ret == SI_KERNEL);
	TEST_RES(sigsegv_on_alt_stack, _ret);
	// The signal mask and the registers are restored before the FPU context
	// fails. The FPU context is then reset, and `rt_sigreturn` returns zero.
	TEST_RES(sigismember(&sigsegv_saved_mask, SIGUSR2), _ret == 1);
	TEST_RES(sigsegv_rip, _ret == 0x1234560);
	TEST_RES(sigsegv_rsp, _ret == 0x7654320);
	TEST_RES(sigsegv_rax, _ret == 0);
	TEST_RES(sigsegv_mxcsr, _ret == DEFAULT_MXCSR);

	TEST_SUCC(sigprocmask(SIG_SETMASK, &old_mask, NULL));
	TEST_SUCC(install_handler(SIGSEGV, SIG_DFL, 0));
}
END_TEST()

// Byte offsets in the XSAVE area of a signal frame.
#define FP_OFF_MXCSR 24
#define FP_OFF_SW_BYTES 464
#define FP_OFF_XSTATE_BV 512
#define FP_OFF_XCOMP_BV 520
#define FP_OFF_HDR_RESERVED 528

#define FP_XSTATE_MAGIC1 0x46505853U
#define FP_XSTATE_MAGIC2 0x46505845U

struct fpx_sw_bytes {
	uint32_t magic1;
	uint32_t extended_size;
	uint64_t xfeatures;
	uint32_t xstate_size;
	uint32_t padding[7];
};

enum fpu_corruption {
	FPU_INTACT,
	FPU_MXCSR_RESERVED,
	FPU_XSTATE_BV_UNSUPPORTED,
	FPU_XCOMP_BV_COMPACTED,
	FPU_HDR_RESERVED,
	FPU_NO_MAGIC1_HDR_RESERVED,
};

static volatile enum fpu_corruption fpu_corruption;
static volatile int fpu_has_magic;

static uint64_t xcr0(void)
{
	uint32_t eax, edx;

	asm volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
	return ((uint64_t)edx << 32) | eax;
}

static void corrupt_fpu_handler(int sig, siginfo_t *info, void *ctx)
{
	ucontext_t *uc = ctx;
	unsigned char *fp = (unsigned char *)uc->uc_mcontext.fpregs;
	struct fpx_sw_bytes *sw = (struct fpx_sw_bytes *)(fp + FP_OFF_SW_BYTES);
	uint64_t bv, unsupported;

	(void)sig;
	(void)info;
	fpu_has_magic = sw->magic1 == FP_XSTATE_MAGIC1 &&
			*(uint32_t *)(fp + sw->xstate_size) == FP_XSTATE_MAGIC2;

	switch (fpu_corruption) {
	case FPU_INTACT:
		break;
	case FPU_MXCSR_RESERVED:
		*(uint32_t *)(fp + FP_OFF_MXCSR) |= 1U << 31;
		break;
	case FPU_XSTATE_BV_UNSUPPORTED:
		unsupported = ~xcr0() & ~(1ULL << 63);
		bv = unsupported & -unsupported;
		*(uint64_t *)(fp + FP_OFF_XSTATE_BV) |= bv;
		break;
	case FPU_XCOMP_BV_COMPACTED:
		*(uint64_t *)(fp + FP_OFF_XCOMP_BV) |= 1ULL << 63;
		break;
	case FPU_HDR_RESERVED:
		fp[FP_OFF_HDR_RESERVED] = 1;
		break;
	case FPU_NO_MAGIC1_HDR_RESERVED:
		// Without the magic, only the legacy area is restored, so the
		// XSAVE header is ignored.
		sw->magic1 = 0;
		fp[FP_OFF_HDR_RESERVED] = 1;
		break;
	}
}

static int sigreturn_with_fpu(enum fpu_corruption corruption)
{
	reset_records();
	fpu_corruption = corruption;
	fpu_has_magic = 0;
	if (sigsetjmp(jmp_env, 1) == 0)
		raise(SIGUSR1);
	return sigsegv_count;
}

FN_TEST(sigreturn_with_invalid_xsave_image)
{
	TEST_SUCC(install_handler(SIGUSR1, corrupt_fpu_handler, SA_SIGINFO));
	TEST_SUCC(install_handler(SIGSEGV, sigsegv_handler,
				  SA_SIGINFO | SA_ONSTACK | SA_NODEFER));

	// The frame carries the software-reserved bytes and the trailing magic.
	TEST_RES(sigreturn_with_fpu(FPU_INTACT), _ret == 0 && fpu_has_magic);
	TEST_RES(sigreturn_with_fpu(FPU_NO_MAGIC1_HDR_RESERVED), _ret == 0);

	TEST_RES(sigreturn_with_fpu(FPU_MXCSR_RESERVED),
		 _ret == 1 && sigsegv_code == SI_KERNEL &&
			 sigsegv_mxcsr == DEFAULT_MXCSR);
	TEST_RES(sigreturn_with_fpu(FPU_XSTATE_BV_UNSUPPORTED),
		 _ret == 1 && sigsegv_code == SI_KERNEL);
	TEST_RES(sigreturn_with_fpu(FPU_XCOMP_BV_COMPACTED),
		 _ret == 1 && sigsegv_code == SI_KERNEL);
	TEST_RES(sigreturn_with_fpu(FPU_HDR_RESERVED),
		 _ret == 1 && sigsegv_code == SI_KERNEL);

	TEST_SUCC(install_handler(SIGUSR1, SIG_DFL, 0));
	TEST_SUCC(install_handler(SIGSEGV, SIG_DFL, 0));
}
END_TEST()

static void sigreturn_with_invalid_mxcsr(void)
{
	install_handler(SIGUSR1, corrupt_fpu_handler, SA_SIGINFO);
	fpu_corruption = FPU_MXCSR_RESERVED;
	raise(SIGUSR1);
}

FN_TEST(sigreturn_with_invalid_xsave_image_kills)
{
	pid_t pid;
	int status;

	TEST_CHILD_KILLED_BY_SIGSEGV(sigreturn_with_invalid_mxcsr);
}
END_TEST()
