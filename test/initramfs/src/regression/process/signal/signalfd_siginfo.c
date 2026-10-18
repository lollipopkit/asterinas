// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

#define TIMER_SIG (SIGRTMIN + 1)
#define TEST_PTR ((void *)0x1122334455667788UL)

static int sfd;
static sigset_t mask;

FN_SETUP(install_signalfd)
{
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGRTMIN);
	sigaddset(&mask, TIMER_SIG);
	sigaddset(&mask, SIGALRM);
	sigaddset(&mask, SIGCHLD);
	sigaddset(&mask, SIGBUS);
	sigaddset(&mask, SIGSEGV);
	sigaddset(&mask, SIGSYS);
	CHECK(sigprocmask(SIG_BLOCK, &mask, NULL));

	sigset_t blocked;
	sigemptyset(&blocked);
	sigaddset(&blocked, SIGUSR2);
	CHECK(sigprocmask(SIG_BLOCK, &blocked, NULL));

	sfd = CHECK(signalfd(-1, &mask, SFD_CLOEXEC));
}
END_SETUP()

static struct signalfd_siginfo fdsi;

FN_TEST(kill_pid_uid)
{
	TEST_SUCC(kill(getpid(), SIGUSR1));

	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) && fdsi.ssi_signo == SIGUSR1 &&
			 fdsi.ssi_code == SI_USER &&
			 fdsi.ssi_pid == (uint32_t)getpid() &&
			 fdsi.ssi_uid == getuid() && fdsi.ssi_int == 0 &&
			 fdsi.ssi_ptr == 0 && fdsi.ssi_status == 0);
}
END_TEST()

FN_TEST(sigqueue_value)
{
	union sigval value = { .sival_ptr = TEST_PTR };
	TEST_SUCC(sigqueue(getpid(), SIGRTMIN, value));

	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) && fdsi.ssi_signo == (uint32_t)SIGRTMIN &&
			 fdsi.ssi_code == SI_QUEUE &&
			 fdsi.ssi_pid == (uint32_t)getpid() &&
			 fdsi.ssi_uid == getuid() &&
			 fdsi.ssi_ptr == (uint64_t)(uintptr_t)TEST_PTR &&
			 fdsi.ssi_int == (int32_t)0x55667788);
}
END_TEST()

FN_TEST(rt_sigqueueinfo_raw)
{
	siginfo_t info;

	// The kernel does not override the user-provided sender for negative codes.
	memset(&info, 0, sizeof(info));
	info.si_code = SI_QUEUE;
	info.si_pid = 12345;
	info.si_uid = 678;
	info.si_value.sival_int = 42;
	TEST_SUCC(syscall(SYS_rt_sigqueueinfo, getpid(), SIGRTMIN, &info));
	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) && fdsi.ssi_signo == (uint32_t)SIGRTMIN &&
			 fdsi.ssi_code == SI_QUEUE && fdsi.ssi_pid == 12345 &&
			 fdsi.ssi_uid == 678 && fdsi.ssi_int == 42);

	TEST_SUCC(syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), SIGRTMIN,
			  &info));
	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) && fdsi.ssi_signo == (uint32_t)SIGRTMIN &&
			 fdsi.ssi_pid == 12345 && fdsi.ssi_int == 42);

	// A SIGCHLD-specific code uses the SIGCHLD layout.
	memset(&info, 0, sizeof(info));
	info.si_code = CLD_EXITED;
	info.si_pid = 12345;
	info.si_uid = 678;
	info.si_status = 9;
	info.si_utime = 11;
	info.si_stime = 22;
	TEST_SUCC(syscall(SYS_rt_sigqueueinfo, getpid(), SIGCHLD, &info));
	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) && fdsi.ssi_signo == SIGCHLD &&
			 fdsi.ssi_code == CLD_EXITED && fdsi.ssi_pid == 12345 &&
			 fdsi.ssi_uid == 678 && fdsi.ssi_status == 9 &&
			 fdsi.ssi_utime == 11 && fdsi.ssi_stime == 22);

	// A code that is not specific to the signal uses the SIGPOLL layout.
	memset(&info, 0, sizeof(info));
	info.si_code = POLL_HUP;
	info.si_band = 0x1234;
	info.si_fd = 5;
	TEST_SUCC(syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1, &info));
	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) && fdsi.ssi_signo == SIGUSR1 &&
			 fdsi.ssi_code == POLL_HUP && fdsi.ssi_band == 0x1234 &&
			 fdsi.ssi_fd == 5 && fdsi.ssi_pid == 0);
}
END_TEST()

FN_TEST(rt_sigqueueinfo_fault_and_sys)
{
	siginfo_t info;

	memset(&info, 0, sizeof(info));
	info.si_code = BUS_MCEERR_AR;
	info.si_addr = TEST_PTR;
	info.si_addr_lsb = 12;
	TEST_SUCC(syscall(SYS_rt_sigqueueinfo, getpid(), SIGBUS, &info));
	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) && fdsi.ssi_signo == SIGBUS &&
			 fdsi.ssi_code == BUS_MCEERR_AR &&
			 fdsi.ssi_addr == (uint64_t)(uintptr_t)TEST_PTR &&
			 fdsi.ssi_addr_lsb == 12 && fdsi.ssi_trapno == 0);

	// `SEGV_BNDERR` is reported like other faults.
	memset(&info, 0, sizeof(info));
	info.si_code = SEGV_BNDERR;
	info.si_addr = TEST_PTR;
	info.si_lower = (void *)0x10;
	TEST_SUCC(syscall(SYS_rt_sigqueueinfo, getpid(), SIGSEGV, &info));
	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) && fdsi.ssi_signo == SIGSEGV &&
			 fdsi.ssi_code == SEGV_BNDERR &&
			 fdsi.ssi_addr == (uint64_t)(uintptr_t)TEST_PTR &&
			 fdsi.ssi_addr_lsb == 0);

	memset(&info, 0, sizeof(info));
	info.si_code = SYS_SECCOMP;
	info.si_call_addr = TEST_PTR;
	info.si_syscall = 39;
	info.si_arch = 0xc000003e;
	TEST_SUCC(syscall(SYS_rt_sigqueueinfo, getpid(), SIGSYS, &info));
	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) && fdsi.ssi_signo == SIGSYS &&
			 fdsi.ssi_code == SYS_SECCOMP &&
			 fdsi.ssi_call_addr == (uint64_t)(uintptr_t)TEST_PTR &&
			 fdsi.ssi_syscall == 39 &&
			 fdsi.ssi_arch == 0xc000003e && fdsi.ssi_addr == 0);
}
END_TEST()

FN_TEST(rt_sigqueueinfo_errors)
{
	siginfo_t info;
	memset(&info, 0, sizeof(info));

	// Pretending to be `kill()` is only allowed for the current thread.
	info.si_code = SI_USER;
	pid_t pid = TEST_SUCC(fork());
	if (pid == 0) {
		pause();
		_exit(0);
	}
	TEST_ERRNO(syscall(SYS_rt_sigqueueinfo, pid, SIGUSR1, &info), EPERM);
	TEST_ERRNO(syscall(SYS_rt_sigqueueinfo, -1, SIGUSR1, &info), EPERM);
	info.si_code = SI_QUEUE;
	TEST_ERRNO(syscall(SYS_rt_sigqueueinfo, -1, SIGUSR1, &info), ESRCH);
	TEST_SUCC(kill(pid, SIGKILL));
	TEST_RES(waitpid(pid, NULL, 0), _ret == pid);
	// Drain the `SIGCHLD`.
	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) && fdsi.ssi_signo == SIGCHLD &&
			 fdsi.ssi_code == CLD_KILLED);

	TEST_ERRNO(syscall(SYS_rt_sigqueueinfo, getpid(), 65, &info), EINVAL);
	TEST_ERRNO(syscall(SYS_rt_tgsigqueueinfo, 0, gettid(), SIGUSR1, &info),
		   EINVAL);
	TEST_ERRNO(syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1, NULL),
		   EFAULT);

	// An unknown code cannot use the trailing bytes.
	info.si_code = SI_DETHREAD - 1;
	((char *)&info)[sizeof(info) - 1] = 1;
	TEST_ERRNO(syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR2, &info),
		   E2BIG);
}
END_TEST()

FN_TEST(trailing_bytes_are_dropped)
{
	siginfo_t info;
	memset(&info, 0, sizeof(info));
	info.si_code = SI_QUEUE;
	info.si_value.sival_int = 7;
	((char *)&info)[sizeof(info) - 1] = 1;
	TEST_SUCC(syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR2, &info));

	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR2);
	memset(&info, 0xff, sizeof(info));
	TEST_RES(sigwaitinfo(&set, &info),
		 _ret == SIGUSR2 && info.si_code == SI_QUEUE &&
			 info.si_value.sival_int == 7 &&
			 ((char *)&info)[sizeof(info) - 1] == 0);
}
END_TEST()

FN_TEST(sigchld_exited)
{
	pid_t pid = TEST_SUCC(fork());
	if (pid == 0)
		_exit(7);

	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) && fdsi.ssi_signo == SIGCHLD &&
			 fdsi.ssi_code == CLD_EXITED &&
			 fdsi.ssi_pid == (uint32_t)pid &&
			 fdsi.ssi_uid == getuid() && fdsi.ssi_status == 7);

	TEST_RES(waitpid(pid, NULL, 0), _ret == pid);
}
END_TEST()

static const struct itimerspec expire_soon = {
	.it_value = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 },
};

FN_TEST(posix_timer_sigevent)
{
	struct sigevent sev;
	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = TIMER_SIG;
	sev.sigev_value.sival_ptr = TEST_PTR;

	// Use raw system calls to get the kernel timer ID.
	int timer_id;
	TEST_SUCC(syscall(SYS_timer_create, CLOCK_MONOTONIC, &sev, &timer_id));
	TEST_SUCC(syscall(SYS_timer_settime, timer_id, 0, &expire_soon, NULL));

	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) &&
			 fdsi.ssi_signo == (uint32_t)TIMER_SIG &&
			 fdsi.ssi_code == SI_TIMER &&
			 fdsi.ssi_tid == (uint32_t)timer_id &&
			 fdsi.ssi_overrun == 0 &&
			 fdsi.ssi_ptr == (uint64_t)(uintptr_t)TEST_PTR &&
			 fdsi.ssi_int == (int32_t)0x55667788 &&
			 fdsi.ssi_pid == 0 && fdsi.ssi_uid == 0);

	TEST_SUCC(syscall(SYS_timer_delete, timer_id));
}
END_TEST()

FN_TEST(posix_timer_default_sigevent)
{
	// Create a timer first so that the default timer's ID is not 0.
	int first_id, timer_id;
	TEST_SUCC(syscall(SYS_timer_create, CLOCK_MONOTONIC, NULL, &first_id));
	TEST_SUCC(syscall(SYS_timer_create, CLOCK_MONOTONIC, NULL, &timer_id));
	TEST_SUCC(syscall(SYS_timer_settime, timer_id, 0, &expire_soon, NULL));

	TEST_RES(read(sfd, &fdsi, sizeof(fdsi)),
		 _ret == sizeof(fdsi) && fdsi.ssi_signo == SIGALRM &&
			 fdsi.ssi_code == SI_TIMER &&
			 fdsi.ssi_tid == (uint32_t)timer_id &&
			 fdsi.ssi_int == timer_id && fdsi.ssi_overrun == 0);

	TEST_SUCC(syscall(SYS_timer_delete, timer_id));
	TEST_SUCC(syscall(SYS_timer_delete, first_id));
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(close(sfd));
}
END_SETUP()
