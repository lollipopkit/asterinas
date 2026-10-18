// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <linux/sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../common/test.h"

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
