// SPDX-License-Identifier: MPL-2.0

/*
 * Regression tests for `/dev/agent_ctl` and tool-call transactions (TCTs).
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../common/test.h"

#define AGENT_CTL_DEVICE "/dev/agent_ctl"

struct agent_ctl_tct_end {
	uint64_t id;
	uint64_t nr_live_processes;
};

struct agent_ctl_tct_begin {
	uint32_t flags;
	uint32_t reserved;
	uint64_t id;
};

#define AGENT_CTL_TCT_DEFER_SYNC (1 << 0)

#define AGENT_CTL_TCT_BEGIN _IOWR(0xA7, 1, struct agent_ctl_tct_begin)
#define AGENT_CTL_TCT_END _IOWR(0xA7, 2, struct agent_ctl_tct_end)
#define AGENT_CTL_TCT_GET _IOR(0xA7, 3, uint64_t)

struct agent_ctl_tct_effects {
	uint64_t id;
	uint64_t buf;
	uint64_t len;
};

#define AGENT_CTL_TCT_EFFECTS _IOWR(0xA7, 4, struct agent_ctl_tct_effects)
#define AGENT_CTL_TCT_RELEASE _IOW(0xA7, 5, uint64_t)
#define AGENT_CTL_TCT_COMMIT _IOW(0xA7, 6, uint64_t)

#define NOBODY_UID 65534

static int ctl_fd;

/* Runs the statements in a child and checks that all of their tests pass. */
#define IN_CHILD(...)                                                          \
	do {                                                                   \
		int __status;                                                  \
		pid_t __child = TEST_SUCC(fork());                             \
		if (__child == 0) {                                            \
			int __failed_before = __tests_failed;                  \
			__VA_ARGS__;                                           \
			_exit(__tests_failed != __failed_before);              \
		}                                                              \
		TEST_RES(waitpid(__child, &__status, 0),                       \
			 _ret == __child && WIFEXITED(__status) &&             \
				 WEXITSTATUS(__status) == 0);                  \
	} while (0)

static uint64_t tct_get(void)
{
	uint64_t id = UINT64_MAX;

	if (ioctl(ctl_fd, AGENT_CTL_TCT_GET, &id) < 0)
		return UINT64_MAX;
	return id;
}

static uint64_t tct_begin_with_flags(uint32_t flags)
{
	struct agent_ctl_tct_begin begin = { .flags = flags };

	if (ioctl(ctl_fd, AGENT_CTL_TCT_BEGIN, &begin) < 0)
		return 0;
	return begin.id;
}

static uint64_t tct_begin(void)
{
	return tct_begin_with_flags(0);
}

static int tct_end(uint64_t id, uint64_t *nr_live_processes)
{
	struct agent_ctl_tct_end end = { .id = id, .nr_live_processes = -1 };
	int ret = ioctl(ctl_fd, AGENT_CTL_TCT_END, &end);

	*nr_live_processes = end.nr_live_processes;
	return ret;
}

static int tct_release(uint64_t id)
{
	return ioctl(ctl_fd, AGENT_CTL_TCT_RELEASE, &id);
}

static int tct_commit(uint64_t id)
{
	return ioctl(ctl_fd, AGENT_CTL_TCT_COMMIT, &id);
}

/* Runs the statements in a child that begins a TCT, and returns the TCT's ID. */
#define IN_TCT(...) IN_TCT_WITH_FLAGS(0, __VA_ARGS__)

/* Like `IN_TCT`, but begins the TCT with `flags`. */
#define IN_TCT_WITH_FLAGS(flags, ...)                                          \
	({                                                                     \
		int __id_pipe[2];                                              \
		uint64_t __id = 0;                                             \
		TEST_SUCC(pipe(__id_pipe));                                    \
		IN_CHILD({                                                     \
			uint64_t __self_id = TEST_RES(                         \
				tct_begin_with_flags(flags), _ret != 0);       \
			TEST_RES(write(__id_pipe[1], &__self_id,               \
				       sizeof(__self_id)),                     \
				 _ret == sizeof(__self_id));                   \
			__VA_ARGS__;                                           \
		});                                                            \
		TEST_RES(read(__id_pipe[0], &__id, sizeof(__id)),              \
			 _ret == sizeof(__id));                                \
		TEST_SUCC(close(__id_pipe[0]));                                \
		TEST_SUCC(close(__id_pipe[1]));                                \
		__id;                                                          \
	})

/*
 * When executed with `get <id>`, checks that the process is in the TCT `<id>`.
 */
FN_SETUP(exec_helper)
{
	int argc = 0;
	char buf[4096];
	char *argv[4];
	int fd = CHECK(open("/proc/self/cmdline", O_RDONLY));
	ssize_t len = CHECK(read(fd, buf, sizeof(buf) - 1));

	CHECK(close(fd));
	buf[len] = '\0';
	for (char *p = buf; p < buf + len && argc < 4; p += strlen(p) + 1)
		argv[argc++] = p;

	ctl_fd = CHECK(open(AGENT_CTL_DEVICE, O_RDONLY));

	if (argc == 3 && strcmp(argv[1], "get") == 0)
		exit(tct_get() == strtoull(argv[2], NULL, 10) ? 0 : 1);
}
END_SETUP()

FN_TEST(device_node)
{
	struct stat st;

	TEST_RES(fstat(ctl_fd, &st),
		 S_ISCHR(st.st_mode) && major(st.st_rdev) == 10 &&
			 minor(st.st_rdev) == 240 &&
			 (st.st_mode & 0777) == 0600);
	TEST_ERRNO(ioctl(ctl_fd, _IO(0xA7, 0)), ENOTTY);
}
END_TEST()

FN_TEST(outside_a_tct)
{
	uint64_t nr_live;

	TEST_RES(tct_get(), _ret == 0);
	TEST_ERRNO(tct_end(0, &nr_live), EINVAL);
	TEST_ERRNO(tct_end(UINT64_MAX, &nr_live), EINVAL);
}
END_TEST()

FN_TEST(begin_and_end)
{
	int pipe_fds[2];
	uint64_t id = 0, nr_live;

	TEST_SUCC(pipe(pipe_fds));
	IN_CHILD({
		uint64_t self_id = TEST_RES(tct_begin(), _ret != 0);
		TEST_RES(tct_get(), _ret == self_id);
		TEST_RES(write(pipe_fds[1], &self_id, sizeof(self_id)),
			 _ret == sizeof(self_id));

		// A process in a TCT cannot join another TCT or end its TCT.
		TEST_ERRNO(tct_begin(), EPERM);
		TEST_ERRNO(tct_end(self_id, &nr_live), EPERM);

		// The TCT is inherited by children.
		int status;
		IN_CHILD({ TEST_RES(tct_get(), _ret == self_id); });

		// The TCT is kept across exec.
		char id_str[32];
		snprintf(id_str, sizeof(id_str), "%llu",
			 (unsigned long long)self_id);
		pid_t exec_child = TEST_SUCC(fork());
		if (exec_child == 0) {
			execl("/proc/self/exe", "agent_ctl", "get", id_str,
			      NULL);
			_exit(2);
		}
		TEST_RES(waitpid(exec_child, &status, 0),
			 _ret == exec_child && WIFEXITED(status) &&
				 WEXITSTATUS(status) == 0);
	});
	TEST_RES(read(pipe_fds[0], &id, sizeof(id)), _ret == sizeof(id));
	TEST_SUCC(close(pipe_fds[0]));
	TEST_SUCC(close(pipe_fds[1]));

	// All processes of the TCT have exited.
	TEST_RES(tct_end(id, &nr_live), _ret == 0 && nr_live == 0);
	TEST_ERRNO(tct_end(id, &nr_live), EINVAL);
	TEST_RES(tct_get(), _ret == 0);

	// An ended TCT is kept until it is released.
	TEST_SUCC(tct_release(id));
	TEST_ERRNO(tct_release(id), EINVAL);
	TEST_ERRNO(tct_end(id, &nr_live), EINVAL);

	// A new TCT gets a new ID.
	IN_CHILD({ TEST_RES(tct_begin(), _ret > id); });
}
END_TEST()

FN_TEST(processes_outliving_the_tct)
{
	int status, id_pipe[2], hold_pipe[2];
	uint64_t id = 0, nr_live;
	char byte;

	TEST_SUCC(prctl(PR_SET_CHILD_SUBREAPER, 1));
	TEST_SUCC(pipe(id_pipe));
	TEST_SUCC(pipe(hold_pipe));
	IN_CHILD({
		uint64_t self_id = TEST_RES(tct_begin(), _ret != 0);
		TEST_RES(write(id_pipe[1], &self_id, sizeof(self_id)),
			 _ret == sizeof(self_id));
		// The grandchild stays alive until the hold pipe is closed.
		if (TEST_SUCC(fork()) == 0) {
			close(hold_pipe[1]);
			_exit(read(hold_pipe[0], &byte, 1) == 0 ? 0 : 1);
		}
	});
	TEST_RES(read(id_pipe[0], &id, sizeof(id)), _ret == sizeof(id));
	TEST_SUCC(close(id_pipe[0]));
	TEST_SUCC(close(id_pipe[1]));
	TEST_SUCC(close(hold_pipe[0]));

	TEST_RES(tct_end(id, &nr_live), _ret == 0 && nr_live == 1);

	TEST_SUCC(close(hold_pipe[1]));
	TEST_RES(wait(&status), _ret > 0 && WIFEXITED(status) &&
					WEXITSTATUS(status) == 0);
	TEST_SUCC(prctl(PR_SET_CHILD_SUBREAPER, 0));
}
END_TEST()

FN_TEST(requires_cap_sys_admin)
{
	uint64_t nr_live;

	IN_CHILD({
		TEST_SUCC(setuid(NOBODY_UID));
		TEST_ERRNO(tct_begin(), EPERM);
		TEST_ERRNO(tct_end(1, &nr_live), EPERM);
		TEST_ERRNO(tct_release(1), EPERM);
		TEST_RES(tct_get(), _ret == 0);
		TEST_ERRNO(open(AGENT_CTL_DEVICE, O_RDONLY), EACCES);
	});
}
END_TEST()

#define EFFECT_DIR "/tmp/agent_ctl_effects"

/* Returns whether `effects` has an entry tagged `tag` whose target is `target`. */
static int has_effect(const char *effects, size_t len, char tag,
		      const char *target)
{
	for (const char *p = effects; p < effects + len; p += strlen(p) + 1) {
		if (p[0] == tag && strcmp(p + 1, target) == 0)
			return 1;
	}
	return 0;
}

/* Returns whether `effects` has an entry tagged `tag` whose target ends with `suffix`. */
static int has_effect_suffix(const char *effects, size_t len, char tag,
			     const char *suffix)
{
	size_t suffix_len = strlen(suffix);

	for (const char *p = effects; p < effects + len; p += strlen(p) + 1) {
		size_t target_len = strlen(p + 1);
		if (p[0] == tag && target_len >= suffix_len &&
		    strcmp(p + 1 + target_len - suffix_len, suffix) == 0)
			return 1;
	}
	return 0;
}

/* Returns the number of entries in `effects` tagged `tag`. */
static int count_effects(const char *effects, size_t len, char tag)
{
	int nr = 0;

	for (const char *p = effects; p < effects + len; p += strlen(p) + 1)
		nr += p[0] == tag;
	return nr;
}

FN_TEST(effects)
{
	static char effects[65536];
	struct agent_ctl_tct_effects args;
	uint64_t id, nr_live;
	int fd;

	CHECK_WITH(mkdir(EFFECT_DIR, 0755), _ret == 0 || errno == EEXIST);
	CHECK(close(CHECK(open(EFFECT_DIR "/read", O_CREAT | O_WRONLY, 0644))));
	fd = CHECK(open(EFFECT_DIR "/script", O_CREAT | O_WRONLY, 0755));
	CHECK(write(fd, "#!/bin/sh\nexit 0\n", 18));
	CHECK(close(fd));
	fd = CHECK(open(EFFECT_DIR "/bad_exec", O_CREAT | O_WRONLY, 0755));
	CHECK(write(fd, "garbage", 7));
	CHECK(close(fd));

	id = IN_TCT({
		char buf[1];
		int fd = TEST_SUCC(open(EFFECT_DIR "/read", O_RDONLY));
		TEST_SUCC(read(fd, buf, sizeof(buf)));
		TEST_SUCC(close(fd));

		TEST_SUCC(close(TEST_SUCC(
			open(EFFECT_DIR "/created", O_CREAT | O_WRONLY, 0644))));
		TEST_SUCC(rename(EFFECT_DIR "/created", EFFECT_DIR "/renamed"));
		TEST_SUCC(unlink(EFFECT_DIR "/renamed"));
		TEST_SUCC(mkdir(EFFECT_DIR "/dir", 0755));
		TEST_SUCC(rmdir(EFFECT_DIR "/dir"));
		TEST_SUCC(chmod(EFFECT_DIR "/read", 0644));

		TEST_ERRNO(open(EFFECT_DIR "/missing", O_RDONLY), ENOENT);
		TEST_ERRNO(access(EFFECT_DIR "/missing_dir/file", F_OK),
			   ENOENT);

		DIR *dir = opendir(EFFECT_DIR);
		TEST_RES(dir != NULL, _ret);
		while (readdir(dir) != NULL)
			;
		TEST_SUCC(closedir(dir));

		char id_str[32];
		snprintf(id_str, sizeof(id_str), "%llu",
			 (unsigned long long)tct_get());
		IN_CHILD({
			execl("/proc/self/exe", "agent_ctl", "get", id_str,
			      NULL);
			_exit(2);
		});

		IN_CHILD({
			execl(EFFECT_DIR "/script", "script", NULL);
			_exit(2);
		});
		// Failed executions are not recorded.
		TEST_ERRNO(execl(EFFECT_DIR "/bad_exec", "bad_exec", NULL),
			   ENOEXEC);

		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = htons(9),
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		};
		int sk = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
		TEST_SUCC(connect(sk, (struct sockaddr *)&addr, sizeof(addr)));
		addr.sin_port = htons(10);
		TEST_SUCC(sendto(sk, "x", 1, 0, (struct sockaddr *)&addr,
				 sizeof(addr)));
		TEST_SUCC(close(sk));

		// Failed connections are not recorded.
		addr.sin_port = htons(1);
		sk = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
		TEST_ERRNO(connect(sk, (struct sockaddr *)&addr, sizeof(addr)),
			   ECONNREFUSED);
		TEST_SUCC(close(sk));
	});

	// Effects of processes outside the TCT are not recorded.
	fd = TEST_SUCC(open(EFFECT_DIR "/outside", O_CREAT | O_WRONLY, 0644));
	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(EFFECT_DIR "/outside"));

	// The effects stay available after the TCT ends.
	TEST_RES(tct_end(id, &nr_live), _ret == 0 && nr_live == 0);

	args = (struct agent_ctl_tct_effects){ .id = id, .buf = 0, .len = 0 };
	TEST_ERRNO(ioctl(ctl_fd, AGENT_CTL_TCT_EFFECTS, &args), ERANGE);
	TEST_RES(args.len, _ret > 0 && _ret <= sizeof(effects));
	args.buf = (uint64_t)effects;
	args.len = sizeof(effects);
	TEST_RES(ioctl(ctl_fd, AGENT_CTL_TCT_EFFECTS, &args),
		 _ret == 0 && args.len > 0 && effects[args.len - 1] == '\0');

	size_t len = args.len;
	TEST_RES(has_effect(effects, len, 'r', EFFECT_DIR "/read"), _ret);
	TEST_RES(has_effect(effects, len, 'w', EFFECT_DIR "/read"), _ret);
	TEST_RES(has_effect(effects, len, 'w', EFFECT_DIR "/created"), _ret);
	TEST_RES(has_effect(effects, len, 'w', EFFECT_DIR "/renamed"), _ret);
	TEST_RES(has_effect(effects, len, 'w', EFFECT_DIR "/dir"), _ret);
	TEST_RES(has_effect(effects, len, 'm', EFFECT_DIR "/missing"), _ret);
	TEST_RES(has_effect(effects, len, 'm', EFFECT_DIR "/missing_dir"),
		 _ret);
	TEST_RES(has_effect(effects, len, 'l', EFFECT_DIR), _ret);
	TEST_RES(has_effect_suffix(effects, len, 'x', "/agent_ctl"), _ret);
	TEST_RES(has_effect(effects, len, 'c', "127.0.0.1:9"), _ret);
	TEST_RES(has_effect(effects, len, 'c', "127.0.0.1:10"), _ret);
	TEST_RES(has_effect(effects, len, 'c', "127.0.0.1:1"), !_ret);
	// The script, its interpreter, and the helper are executed.
	TEST_RES(has_effect(effects, len, 'x', EFFECT_DIR "/script"), _ret);
	TEST_RES(count_effects(effects, len, 'x'), _ret == 3);
	TEST_RES(has_effect(effects, len, 'x', EFFECT_DIR "/bad_exec"), !_ret);
	TEST_RES(has_effect(effects, len, 'w', EFFECT_DIR "/outside"), !_ret);
	TEST_RES(has_effect(effects, len, '!', ""), !_ret);

	TEST_SUCC(tct_release(id));
	TEST_ERRNO(ioctl(ctl_fd, AGENT_CTL_TCT_EFFECTS, &args), EINVAL);

	TEST_SUCC(unlink(EFFECT_DIR "/read"));
	TEST_SUCC(unlink(EFFECT_DIR "/script"));
	TEST_SUCC(unlink(EFFECT_DIR "/bad_exec"));
	TEST_SUCC(rmdir(EFFECT_DIR));
}
END_TEST()

FN_TEST(release_requires_end)
{
	uint64_t nr_live;
	uint64_t id = IN_TCT({});

	TEST_ERRNO(tct_release(id), EBUSY);
	TEST_RES(tct_end(id, &nr_live), _ret == 0 && nr_live == 0);
	TEST_SUCC(tct_release(id));
}
END_TEST()

FN_TEST(begin_with_bad_pointer)
{
	IN_CHILD({
		// The caller does not join a TCT that it cannot identify.
		TEST_ERRNO(ioctl(ctl_fd, AGENT_CTL_TCT_BEGIN, (void *)1), EFAULT);
		TEST_RES(tct_get(), _ret == 0);
		TEST_RES(tct_begin(), _ret != 0);
	});
}
END_TEST()

#define SYNC_DIR "/ext2/agent_ctl_sync"

FN_TEST(begin_rejects_invalid_flags)
{
	IN_CHILD({
		TEST_ERRNO(tct_begin_with_flags(1 << 31), EINVAL);
		TEST_RES(tct_get(), _ret == 0);
	});
}
END_TEST()

/*
 * Checks that the data written by `writer`, which runs in a TCT begun with `flags`, can be
 * read back after the TCT ends.
 */
#define TEST_SYNCS_IN_TCT(flags)                                               \
	do {                                                                   \
		int __pipe[2];                                                 \
		uint64_t __id = 0, __nr_live;                                  \
		char __buf[8] = { 0 };                                         \
		TEST_SUCC(pipe(__pipe));                                       \
		IN_CHILD({                                                     \
			__id = TEST_RES(tct_begin_with_flags(flags),           \
					_ret != 0);                            \
			TEST_RES(write(__pipe[1], &__id, sizeof(__id)),        \
				 _ret == sizeof(__id));                        \
			int __fd = TEST_SUCC(open(SYNC_DIR "/file",            \
						  O_CREAT | O_RDWR | O_TRUNC,  \
						  0644));                      \
			TEST_RES(write(__fd, "fsync", 5), _ret == 5);          \
			TEST_SUCC(fsync(__fd));                                \
			TEST_SUCC(fdatasync(__fd));                            \
			TEST_SUCC(syncfs(__fd));                               \
			sync();                                                \
			TEST_SUCC(ftruncate(__fd, 4096));                      \
			char *__map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, \
					   MAP_SHARED, __fd, 0);               \
			TEST_RES(__map != MAP_FAILED, _ret);                   \
			__map[5] = 'm';                                        \
			TEST_SUCC(msync(__map, 4096, MS_SYNC));                \
			TEST_SUCC(munmap(__map, 4096));                        \
			TEST_SUCC(close(__fd));                                \
			__fd = TEST_SUCC(open(SYNC_DIR "/file",                \
					      O_WRONLY | O_SYNC));             \
			TEST_RES(pwrite(__fd, "s", 1, 6), _ret == 1);          \
			TEST_SUCC(close(__fd));                                \
			__fd = TEST_SUCC(open(SYNC_DIR "/file",                \
					      O_WRONLY | O_DSYNC));            \
			TEST_RES(pwrite(__fd, "d", 1, 7), _ret == 1);          \
			TEST_SUCC(close(__fd));                                \
		});                                                            \
		TEST_RES(read(__pipe[0], &__id, sizeof(__id)),                 \
			 _ret == sizeof(__id));                                \
		TEST_SUCC(close(__pipe[0]));                                   \
		TEST_SUCC(close(__pipe[1]));                                   \
		TEST_RES(tct_end(__id, &__nr_live), _ret == 0);                \
		TEST_SUCC(tct_commit(__id));                                   \
		TEST_SUCC(tct_release(__id));                                  \
		int __fd = TEST_SUCC(open(SYNC_DIR "/file", O_RDONLY));        \
		TEST_RES(read(__fd, __buf, sizeof(__buf)),                     \
			 _ret == sizeof(__buf) &&                              \
				 memcmp(__buf, "fsyncmsd", 8) == 0);           \
		TEST_SUCC(close(__fd));                                        \
		TEST_SUCC(unlink(SYNC_DIR "/file"));                           \
	} while (0)

FN_TEST(syncs_in_tct)
{
	CHECK_WITH(mkdir(SYNC_DIR, 0755), _ret == 0 || errno == EEXIST);

	TEST_SYNCS_IN_TCT(0);
	TEST_SYNCS_IN_TCT(AGENT_CTL_TCT_DEFER_SYNC);

	TEST_SUCC(rmdir(SYNC_DIR));
}
END_TEST()

FN_TEST(commit_and_release)
{
	uint64_t id, nr_live;

	// A TCT that defers sync requests cannot be released before it is committed.
	id = IN_TCT_WITH_FLAGS(AGENT_CTL_TCT_DEFER_SYNC, {});
	TEST_ERRNO(tct_commit(id), EINVAL);
	TEST_RES(tct_end(id, &nr_live), _ret == 0);
	TEST_ERRNO(tct_release(id), EBUSY);
	TEST_SUCC(tct_commit(id));
	TEST_SUCC(tct_commit(id));
	TEST_SUCC(tct_release(id));

	// Committing a TCT that does not defer sync requests is optional.
	id = IN_TCT({});
	TEST_RES(tct_end(id, &nr_live), _ret == 0);
	TEST_SUCC(tct_release(id));
}
END_TEST()
