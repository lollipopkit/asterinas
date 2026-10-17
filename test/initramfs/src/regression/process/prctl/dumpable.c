// SPDX-License-Identifier: MPL-2.0

/*
 * Tests the dumpability of processes (`PR_GET_DUMPABLE` and `PR_SET_DUMPABLE`)
 * and how it restricts access to processes of the same user.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

#define NOBODY_UID 65534
#define NOREAD_COPY "/tmp/dumpable_noread"

/* When executed with `get`, exits with the dumpability. */
FN_SETUP(exec_helper)
{
	char buf[256];
	int fd = CHECK(open("/proc/self/cmdline", O_RDONLY));
	ssize_t len = CHECK(read(fd, buf, sizeof(buf) - 1));

	CHECK(close(fd));
	buf[len] = '\0';
	if (strlen(buf) + 1 < (size_t)len && strcmp(buf + strlen(buf) + 1, "get") == 0)
		exit(CHECK(prctl(PR_GET_DUMPABLE)));
}
END_SETUP()

/* Runs `path get` in a child after `setup`, and returns the dumpability of the new program. */
#define EXEC_DUMPABLE(path, setup)                                       \
	({                                                               \
		int __status;                                            \
		pid_t __child = TEST_SUCC(fork());                       \
		if (__child == 0) {                                      \
			setup;                                           \
			execl(path, "dumpable", "get", NULL);            \
			_exit(100);                                      \
		}                                                        \
		TEST_RES(waitpid(__child, &__status, 0),                 \
			 _ret == __child && WIFEXITED(__status));        \
		WEXITSTATUS(__status);                                   \
	})

FN_TEST(get_and_set)
{
	TEST_RES(prctl(PR_GET_DUMPABLE), _ret == 1);
	TEST_SUCC(prctl(PR_SET_DUMPABLE, 0));
	TEST_RES(prctl(PR_GET_DUMPABLE), _ret == 0);
	TEST_ERRNO(prctl(PR_SET_DUMPABLE, 2), EINVAL);
	TEST_ERRNO(prctl(PR_SET_DUMPABLE, -1L), EINVAL);

	// The dumpability is inherited by children.
	pid_t child = TEST_SUCC(fork());
	if (child == 0)
		_exit(prctl(PR_GET_DUMPABLE));
	int status;
	TEST_RES(waitpid(child, &status, 0),
		 _ret == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);

	TEST_SUCC(prctl(PR_SET_DUMPABLE, 1));
	TEST_RES(prctl(PR_GET_DUMPABLE), _ret == 1);
}
END_TEST()

FN_TEST(credential_changes)
{
	int status;
	pid_t child = TEST_SUCC(fork());

	if (child == 0) {
		// Setting the same IDs does not change the dumpability.
		CHECK(setresuid(0, 0, 0));
		CHECK_WITH(prctl(PR_GET_DUMPABLE), _ret == 1);
		// Changing the effective user ID makes the process non-dumpable.
		CHECK(setresuid(0, NOBODY_UID, 0));
		CHECK_WITH(prctl(PR_GET_DUMPABLE), _ret == 0);
		_exit(0);
	}
	TEST_RES(waitpid(child, &status, 0),
		 _ret == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()

FN_TEST(exec)
{
	// A new program becomes dumpable again.
	TEST_RES(EXEC_DUMPABLE("/proc/self/exe",
			       CHECK(prctl(PR_SET_DUMPABLE, 0))),
		 _ret == 1);
	// A program run with different effective and real user IDs is not dumpable.
	TEST_RES(EXEC_DUMPABLE("/proc/self/exe",
			       CHECK(setresuid(NOBODY_UID, 0, 0))),
		 _ret == 0);

	// A program that the user cannot read is not dumpable.
	int src = TEST_SUCC(open("/proc/self/exe", O_RDONLY));
	int dst = TEST_SUCC(
		open(NOREAD_COPY, O_CREAT | O_WRONLY | O_TRUNC, 0711));
	char buf[4096];
	ssize_t len;
	while ((len = read(src, buf, sizeof(buf))) > 0)
		TEST_RES(write(dst, buf, len), _ret == len);
	TEST_SUCC(close(src));
	TEST_SUCC(close(dst));
	TEST_RES(EXEC_DUMPABLE(NOREAD_COPY, CHECK(setuid(NOBODY_UID))),
		 _ret == 0);
	TEST_SUCC(chmod(NOREAD_COPY, 0755));
	TEST_RES(EXEC_DUMPABLE(NOREAD_COPY, CHECK(setuid(NOBODY_UID))),
		 _ret == 1);
	TEST_SUCC(unlink(NOREAD_COPY));
}
END_TEST()

FN_TEST(access_from_same_user)
{
	int cmd_pipe[2], ack_pipe[2], status;
	char byte, path[64], buf[PATH_MAX];
	struct stat st;
	pid_t target, reader;

	TEST_SUCC(pipe(cmd_pipe));
	TEST_SUCC(pipe(ack_pipe));
	target = TEST_SUCC(fork());
	if (target == 0) {
		CHECK(setresuid(NOBODY_UID, NOBODY_UID, NOBODY_UID));
		while (read(cmd_pipe[0], &byte, 1) == 1 && byte != 'q') {
			CHECK(prctl(PR_SET_DUMPABLE, byte == 'u'));
			CHECK_WITH(write(ack_pipe[1], "A", 1), _ret == 1);
		}
		_exit(0);
	}
	TEST_SUCC(close(cmd_pipe[0]));
	TEST_SUCC(close(ack_pipe[1]));

#define SET_TARGET_DUMPABLE(cmd)                               \
	TEST_RES(write(cmd_pipe[1], cmd, 1), _ret == 1);       \
	TEST_RES(read(ack_pipe[0], &byte, 1), _ret == 1)

	snprintf(path, sizeof(path), "/proc/%d/exe", target);

	// Changing the user IDs has made the target non-dumpable.
	SET_TARGET_DUMPABLE("d");
	reader = TEST_SUCC(fork());
	if (reader == 0) {
		CHECK(setuid(NOBODY_UID));
		CHECK_WITH(readlink(path, buf, sizeof(buf)),
			   _ret < 0 && errno == EACCES);
		_exit(0);
	}
	TEST_RES(waitpid(reader, &status, 0),
		 _ret == reader && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 0);

	// The files of a non-dumpable process are owned by root, except for its
	// directory.
	snprintf(path, sizeof(path), "/proc/%d/status", target);
	TEST_RES(stat(path, &st), _ret == 0 && st.st_uid == 0);
	snprintf(path, sizeof(path), "/proc/%d", target);
	TEST_RES(stat(path, &st), _ret == 0 && st.st_uid == NOBODY_UID);

	SET_TARGET_DUMPABLE("u");
	snprintf(path, sizeof(path), "/proc/%d/status", target);
	TEST_RES(stat(path, &st), _ret == 0 && st.st_uid == NOBODY_UID);
	snprintf(path, sizeof(path), "/proc/%d/exe", target);
	reader = TEST_SUCC(fork());
	if (reader == 0) {
		CHECK(setuid(NOBODY_UID));
		CHECK_WITH(readlink(path, buf, sizeof(buf)), _ret > 0);
		_exit(0);
	}
	TEST_RES(waitpid(reader, &status, 0),
		 _ret == reader && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 0);

	TEST_RES(write(cmd_pipe[1], "q", 1), _ret == 1);
	TEST_RES(waitpid(target, &status, 0),
		 _ret == target && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 0);
	TEST_SUCC(close(cmd_pipe[1]));
	TEST_SUCC(close(ack_pipe[0]));
}
END_TEST()
