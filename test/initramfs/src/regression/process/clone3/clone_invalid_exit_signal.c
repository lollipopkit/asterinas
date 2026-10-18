// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <linux/sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../common/test.h"

#ifndef CLONE_CLEAR_SIGHAND
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif

static pid_t sys_clone3(struct clone_args *args)
{
	return syscall(SYS_clone3, args, sizeof(struct clone_args));
}

FN_TEST(clone_rejects_invalid_exit_signal)
{
	// Like `clone3`, `clone` rejects invalid exit signals.
	TEST_ERRNO(syscall(SYS_clone, 65UL, 0UL, 0UL, 0UL, 0UL), EINVAL);
	TEST_ERRNO(syscall(SYS_clone, 255UL, 0UL, 0UL, 0UL, 0UL), EINVAL);
}
END_TEST()

FN_TEST(clone3_rejects_invalid_exit_signal)
{
	struct clone_args args = {};

	args.exit_signal = 0xff;
	TEST_ERRNO(sys_clone3(&args), EINVAL);

	args.exit_signal = 0x101;
	TEST_ERRNO(sys_clone3(&args), EINVAL);
}
END_TEST()
FN_TEST(clone3_rejects_invalid_flags)
{
	struct clone_args args = { .exit_signal = SIGCHLD };

	// Unknown flags above bit 31 are not silently dropped.
	args.flags = 1ULL << 40;
	TEST_ERRNO(sys_clone3(&args), EINVAL);

	// `CLONE_DETACHED` and the `CSIGNAL` bits are reserved for `clone3`.
	args.flags = CLONE_DETACHED;
	TEST_ERRNO(sys_clone3(&args), EINVAL);
	args.flags = 0x1;
	TEST_ERRNO(sys_clone3(&args), EINVAL);
}
END_TEST()

static void handler(int sig)
{
	(void)sig;
}

FN_TEST(clone3_clear_sighand)
{
	struct clone_args args = { .exit_signal = SIGCHLD };
	struct sigaction sa = { .sa_handler = handler };
	int status;
	pid_t pid;

	CHECK(sigaction(SIGUSR1, &sa, NULL));
	CHECK_WITH(signal(SIGUSR2, SIG_IGN), _ret != SIG_ERR);

	// Handled signals are reset to `SIG_DFL`, while ignored signals stay ignored.
	args.flags = CLONE_CLEAR_SIGHAND;
	pid = TEST_SUCC(sys_clone3(&args));
	if (pid == 0) {
		struct sigaction old;

		if (sigaction(SIGUSR1, NULL, &old) < 0 || old.sa_handler != SIG_DFL)
			_exit(1);
		if (sigaction(SIGUSR2, NULL, &old) < 0 || old.sa_handler != SIG_IGN)
			_exit(2);
		_exit(0);
	}
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);

	// The handlers of the parent are unchanged.
	TEST_RES(sigaction(SIGUSR1, NULL, &sa), sa.sa_handler == handler);

	// Shared handlers cannot be cleared.
	args.flags = CLONE_CLEAR_SIGHAND | CLONE_SIGHAND | CLONE_VM;
	TEST_ERRNO(sys_clone3(&args), EINVAL);

	CHECK_WITH(signal(SIGUSR1, SIG_DFL), _ret != SIG_ERR);
	CHECK_WITH(signal(SIGUSR2, SIG_DFL), _ret != SIG_ERR);
}
END_TEST()
