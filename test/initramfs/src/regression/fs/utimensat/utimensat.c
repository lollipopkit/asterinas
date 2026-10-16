// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

#define TEST_FILE "/tmp/utimensat_at_empty_path"

static int fd = -1;

FN_SETUP(prepare)
{
	fd = CHECK(open(TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644));
}
END_SETUP()

FN_TEST(at_empty_path_updates_times)
{
	struct timespec times[2] = {
		{ .tv_sec = 1234567890, .tv_nsec = 0 },
		{ .tv_sec = 1234567891, .tv_nsec = 0 },
	};
	TEST_SUCC(utimensat(fd, "", times, AT_EMPTY_PATH));

	struct stat st;
	TEST_RES(fstat(fd, &st), st.st_atim.tv_sec == 1234567890 &&
					 st.st_mtim.tv_sec == 1234567891);
}
END_TEST()

FN_TEST(empty_path_without_flag_returns_enoent)
{
	struct timespec times[2] = {
		{ .tv_sec = 1, .tv_nsec = 0 },
		{ .tv_sec = 1, .tv_nsec = 0 },
	};
	TEST_ERRNO(utimensat(fd, "", times, 0), ENOENT);
}
END_TEST()

FN_TEST(legacy_null_pathname)
{
	struct timespec times[2] = {
		{ .tv_sec = 1000000000, .tv_nsec = 0 },
		{ .tv_sec = 1000000001, .tv_nsec = 0 },
	};
	TEST_SUCC(syscall(SYS_utimensat, fd, NULL, times, 0));

	struct stat st;
	TEST_RES(fstat(fd, &st), st.st_atim.tv_sec == 1000000000 &&
					 st.st_mtim.tv_sec == 1000000001);
}
END_TEST()

FN_TEST(legacy_null_pathname_with_nonzero_flag_returns_einval)
{
	struct timespec times[2] = {
		{ .tv_sec = 1, .tv_nsec = 0 },
		{ .tv_sec = 1, .tv_nsec = 0 },
	};
	TEST_ERRNO(syscall(SYS_utimensat, fd, NULL, times, AT_SYMLINK_NOFOLLOW),
		   EINVAL);
}
END_TEST()

FN_TEST(legacy_null_pathname_with_o_path_returns_ebadf)
{
	int opath_fd = TEST_SUCC(open(TEST_FILE, O_PATH));
	struct timespec times[2] = {
		{ .tv_sec = 10, .tv_nsec = 0 },
		{ .tv_sec = 20, .tv_nsec = 0 },
	};

	TEST_ERRNO(syscall(SYS_utimensat, opath_fd, NULL, times, 0), EBADF);
	TEST_SUCC(syscall(SYS_utimensat, opath_fd, "", times, AT_EMPTY_PATH));

	TEST_SUCC(close(opath_fd));
}
END_TEST()

FN_TEST(at_empty_path_on_o_path_symlink_updates_symlink)
{
	const char *symlink_path = "/tmp/utimensat_symlink";
	TEST_SUCC(symlink(TEST_FILE, symlink_path));
	int sym_fd = TEST_SUCC(open(symlink_path, O_PATH | O_NOFOLLOW));

	struct timespec times[2] = {
		{ .tv_sec = 1500000000, .tv_nsec = 0 },
		{ .tv_sec = 1500000001, .tv_nsec = 0 },
	};
	TEST_SUCC(utimensat(sym_fd, "", times,
			    AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW));

	struct stat sym_st;
	TEST_RES(fstatat(AT_FDCWD, symlink_path, &sym_st, AT_SYMLINK_NOFOLLOW),
		 sym_st.st_atim.tv_sec == 1500000000 &&
			 sym_st.st_mtim.tv_sec == 1500000001);

	TEST_SUCC(close(sym_fd));
	TEST_SUCC(unlink(symlink_path));
}
END_TEST()

#define OTHER_UID 1000

/* Runs `op` as an unprivileged user that does not own `TEST_FILE` and returns its errno. */
#define ERRNO_AS_OTHER_USER(op)                                                \
	({                                                                     \
		int status;                                                    \
		pid_t pid = CHECK(fork());                                     \
		if (pid == 0) {                                                \
			if (setresuid(OTHER_UID, OTHER_UID, OTHER_UID) < 0)     \
				_exit(255);                                    \
			_exit((op) < 0 ? errno : 0);                           \
		}                                                              \
		CHECK(waitpid(pid, &status, 0));                               \
		WEXITSTATUS(status);                                           \
	})

FN_TEST(non_owner_needs_permission)
{
	struct timespec now[2] = { { .tv_nsec = UTIME_NOW },
				   { .tv_nsec = UTIME_NOW } };
	struct timespec explicit[2] = { { .tv_sec = 1 }, { .tv_sec = 2 } };
	struct timespec omit[2] = { { .tv_nsec = UTIME_OMIT },
				    { .tv_nsec = UTIME_OMIT } };

	/* Without write permission, even touching the file is denied. */
	TEST_SUCC(chmod(TEST_FILE, 0644));
	TEST_RES(ERRNO_AS_OTHER_USER(utimensat(AT_FDCWD, TEST_FILE, NULL, 0)),
		 _ret == EACCES);
	TEST_RES(ERRNO_AS_OTHER_USER(utimensat(AT_FDCWD, TEST_FILE, now, 0)),
		 _ret == EACCES);

	/* Write permission allows touching, but not setting explicit times. */
	TEST_SUCC(chmod(TEST_FILE, 0666));
	TEST_RES(ERRNO_AS_OTHER_USER(utimensat(AT_FDCWD, TEST_FILE, NULL, 0)),
		 _ret == 0);
	TEST_RES(ERRNO_AS_OTHER_USER(
			 utimensat(AT_FDCWD, TEST_FILE, explicit, 0)),
		 _ret == EPERM);
	TEST_RES(ERRNO_AS_OTHER_USER(utimensat(AT_FDCWD, TEST_FILE, omit, 0)),
		 _ret == EPERM);
	TEST_SUCC(chmod(TEST_FILE, 0644));
}
END_TEST()

FN_TEST(omit_keeps_the_time)
{
	struct timespec set[2] = { { .tv_sec = 100 }, { .tv_sec = 200 } };
	struct timespec omit_atime[2] = { { .tv_nsec = UTIME_OMIT },
					  { .tv_sec = 300 } };
	struct stat st;

	TEST_SUCC(utimensat(AT_FDCWD, TEST_FILE, set, 0));
	TEST_SUCC(utimensat(AT_FDCWD, TEST_FILE, omit_atime, 0));
	TEST_RES(stat(TEST_FILE, &st),
		 st.st_atim.tv_sec == 100 && st.st_mtim.tv_sec == 300);
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(close(fd));
	CHECK(unlink(TEST_FILE));
}
END_SETUP()
