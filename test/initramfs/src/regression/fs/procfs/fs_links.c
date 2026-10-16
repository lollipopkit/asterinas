// SPDX-License-Identifier: MPL-2.0

/*
 * Tests for `/proc/[pid]/cwd` and `/proc/[pid]/root`.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

#define TEST_DIR "/tmp/proc_fs_links"
#define NOBODY_UID 65534

static char link_buf[PATH_MAX];

/* Reads the link at `path` into `link_buf`. */
static ssize_t read_link(const char *path)
{
	ssize_t len = readlink(path, link_buf, sizeof(link_buf) - 1);

	if (len >= 0)
		link_buf[len] = '\0';
	return len;
}

FN_SETUP(test_dir)
{
	CHECK(mkdir(TEST_DIR, 0755));
	CHECK(close(CHECK(open(TEST_DIR "/file", O_CREAT | O_WRONLY, 0644))));
}
END_SETUP()

FN_TEST(self_links)
{
	char path[64];

	TEST_SUCC(chdir(TEST_DIR));
	TEST_RES(read_link("/proc/self/cwd"), strcmp(link_buf, TEST_DIR) == 0);
	TEST_RES(read_link("/proc/self/root"), strcmp(link_buf, "/") == 0);
	snprintf(path, sizeof(path), "/proc/self/task/%ld/cwd",
		 syscall(SYS_gettid));
	TEST_RES(read_link(path), strcmp(link_buf, TEST_DIR) == 0);

	// The links can be followed.
	TEST_SUCC(close(TEST_SUCC(open("/proc/self/cwd/file", O_RDONLY))));
	TEST_SUCC(access("/proc/self/root" TEST_DIR "/file", F_OK));

	TEST_SUCC(chdir("/"));
	TEST_RES(read_link("/proc/self/cwd"), strcmp(link_buf, "/") == 0);
}
END_TEST()

FN_TEST(other_process_links)
{
	int ready_pipe[2], exit_pipe[2], status;
	char path[64], byte;
	pid_t child;

	TEST_SUCC(pipe(ready_pipe));
	TEST_SUCC(pipe(exit_pipe));
	child = TEST_SUCC(fork());
	if (child == 0) {
		CHECK(chdir(TEST_DIR));
		CHECK_WITH(write(ready_pipe[1], "R", 1), _ret == 1);
		CHECK_WITH(read(exit_pipe[0], &byte, 1), _ret == 1);
		_exit(0);
	}
	TEST_RES(read(ready_pipe[0], &byte, 1), _ret == 1);

	snprintf(path, sizeof(path), "/proc/%d/cwd", child);
	TEST_RES(read_link(path), strcmp(link_buf, TEST_DIR) == 0);

	// Another user cannot read the links.
	pid_t reader = TEST_SUCC(fork());
	if (reader == 0) {
		char root_path[64];

		snprintf(root_path, sizeof(root_path), "/proc/%d/root", child);
		CHECK(setuid(NOBODY_UID));
		CHECK_WITH(read_link(path), _ret < 0 && errno == EACCES);
		CHECK_WITH(open(path, O_RDONLY | O_DIRECTORY),
			   _ret < 0 && errno == EACCES);
		CHECK_WITH(read_link(root_path), _ret < 0 && errno == EACCES);
		CHECK_WITH(open(root_path, O_RDONLY | O_DIRECTORY),
			   _ret < 0 && errno == EACCES);
		_exit(0);
	}
	TEST_RES(waitpid(reader, &status, 0),
		 _ret == reader && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 0);

	// The links of an exited process do not resolve.
	TEST_RES(write(exit_pipe[1], "X", 1), _ret == 1);
	TEST_RES(waitid(P_PID, child, NULL, WEXITED | WNOWAIT), _ret == 0);
	TEST_ERRNO(read_link(path), ENOENT);
	snprintf(path, sizeof(path), "/proc/%d/root", child);
	TEST_ERRNO(read_link(path), ENOENT);

	TEST_RES(waitpid(child, &status, 0), _ret == child && WIFEXITED(status));
	TEST_SUCC(close(ready_pipe[0]));
	TEST_SUCC(close(ready_pipe[1]));
	TEST_SUCC(close(exit_pipe[0]));
	TEST_SUCC(close(exit_pipe[1]));
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(unlink(TEST_DIR "/file"));
	CHECK(rmdir(TEST_DIR));
}
END_SETUP()
