// SPDX-License-Identifier: MPL-2.0

/*
 * Tests that procfs entries exposing the state of another process require
 * the access that Linux checks with `ptrace_may_access`.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

#define NOBODY_UID 65534

static char buf[PATH_MAX];

FN_TEST(own_entries)
{
	TEST_RES(readlink("/proc/self/exe", buf, sizeof(buf)), _ret > 0);
	TEST_RES(readlink("/proc/self/fd/0", buf, sizeof(buf)), _ret > 0);
	TEST_SUCC(close(TEST_SUCC(open("/proc/self/fdinfo/0", O_RDONLY))));
	TEST_SUCC(close(TEST_SUCC(open("/proc/self/environ", O_RDONLY))));
	TEST_SUCC(close(TEST_SUCC(open("/proc/self/auxv", O_RDONLY))));
}
END_TEST()

/* Checks that `path` (formatted with `pid`) cannot be read by the caller. */
static int is_denied(const char *fmt, pid_t pid, int is_link)
{
	char path[64];
	int fd;

	snprintf(path, sizeof(path), fmt, pid);
	if (is_link)
		return readlink(path, buf, sizeof(buf)) < 0 && errno == EACCES;
	fd = open(path, O_RDONLY);
	if (fd >= 0)
		close(fd);
	return fd < 0 && errno == EACCES;
}

FN_TEST(other_user_entries)
{
	int ready_pipe[2], exit_pipe[2], status;
	pid_t target, reader;
	char byte, path[64];

	TEST_SUCC(pipe(ready_pipe));
	TEST_SUCC(pipe(exit_pipe));
	target = TEST_SUCC(fork());
	if (target == 0) {
		// The saved user ID stays root, so an unprivileged user with the
		// same effective user ID still cannot access the process.
		CHECK(setresuid(NOBODY_UID, NOBODY_UID, 0));
		CHECK_WITH(write(ready_pipe[1], "R", 1), _ret == 1);
		CHECK_WITH(read(exit_pipe[0], &byte, 1), _ret == 1);
		_exit(0);
	}
	// Close the unused ends, so the reads below fail instead of blocking if the child fails.
	TEST_SUCC(close(ready_pipe[1]));
	TEST_SUCC(close(exit_pipe[0]));
	TEST_RES(read(ready_pipe[0], &byte, 1), _ret == 1);

	reader = TEST_SUCC(fork());
	if (reader == 0) {
		CHECK(setuid(NOBODY_UID));
		CHECK_WITH(is_denied("/proc/%d/exe", target, 1), _ret);
		CHECK_WITH(is_denied("/proc/%d/fd/0", target, 1), _ret);
		CHECK_WITH(is_denied("/proc/%d/cwd", target, 1), _ret);
		CHECK_WITH(is_denied("/proc/%d/fdinfo/0", target, 0), _ret);
		CHECK_WITH(is_denied("/proc/%d/environ", target, 0), _ret);
		CHECK_WITH(is_denied("/proc/%d/auxv", target, 0), _ret);
		_exit(0);
	}
	TEST_RES(waitpid(reader, &status, 0),
		 _ret == reader && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 0);

	// A privileged user can access the process.
	snprintf(path, sizeof(path), "/proc/%d/exe", target);
	TEST_RES(readlink(path, buf, sizeof(buf)), _ret > 0);
	snprintf(path, sizeof(path), "/proc/%d/environ", target);
	TEST_SUCC(close(TEST_SUCC(open(path, O_RDONLY))));

	// The memory of an exited process cannot be opened.
	TEST_RES(write(exit_pipe[1], "X", 1), _ret == 1);
	TEST_RES(waitid(P_PID, target, NULL, WEXITED | WNOWAIT), _ret == 0);
	TEST_ERRNO(open(path, O_RDONLY), ESRCH);
	snprintf(path, sizeof(path), "/proc/%d/auxv", target);
	TEST_ERRNO(open(path, O_RDONLY), ESRCH);

	TEST_RES(waitpid(target, &status, 0),
		 _ret == target && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 0);
	TEST_SUCC(close(ready_pipe[0]));
	TEST_SUCC(close(exit_pipe[1]));
}
END_TEST()
