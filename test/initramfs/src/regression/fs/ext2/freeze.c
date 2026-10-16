// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"
#include "../../common/block_device.h"

/* From <linux/fs.h>, which conflicts with <sys/mount.h>. */
#define FIFREEZE _IOWR('X', 119, int)
#define FITHAW _IOWR('X', 120, int)

#define MOUNT_DIR "/tmp/freeze"
#define FILE_PATH MOUNT_DIR "/file"
#define DIR_PATH MOUNT_DIR "/dir"
#define TMPFS_DIR "/tmp/freeze_tmpfs"

static int block_device_fd;
static int mount_fd;

FN_SETUP(prepare)
{
	CHECK_WITH(mkdir(MOUNT_DIR, 0755), _ret >= 0 || errno == EEXIST);
	CHECK_WITH(mkdir(TMPFS_DIR, 0755), _ret >= 0 || errno == EEXIST);
	CHECK(unshare(CLONE_NEWNS));
	block_device_fd = CHECK(open_block_device(BLOCK_VDC_EXT2));
	CHECK(mount_block_device(block_device_fd, MOUNT_DIR, "ext2", 0));
	CHECK_WITH(unlink(FILE_PATH), _ret == 0 || errno == ENOENT);
	CHECK_WITH(rmdir(DIR_PATH), _ret == 0 || errno == ENOENT);
	CHECK(close(CHECK(open(FILE_PATH, O_CREAT | O_WRONLY, 0644))));
	mount_fd = CHECK(open(MOUNT_DIR, O_RDONLY | O_DIRECTORY));
}
END_SETUP()

FN_TEST(freeze_and_thaw_report_state_errors)
{
	TEST_SUCC(ioctl(mount_fd, FIFREEZE, 0));
	TEST_ERRNO(ioctl(mount_fd, FIFREEZE, 0), EBUSY);
	TEST_ERRNO(mount(NULL, MOUNT_DIR, NULL, MS_REMOUNT | MS_RDONLY, NULL),
		   EBUSY);
	TEST_SUCC(ioctl(mount_fd, FITHAW, 0));
	TEST_ERRNO(ioctl(mount_fd, FITHAW, 0), EINVAL);
}
END_TEST()

/*
 * Forks a child that runs `op` and checks that it waits until the file system is thawed.
 *
 * The child reports through a pipe right before `op`, so the check does not depend on when
 * the child gets scheduled.
 */
#define TEST_WAITS_WHILE_FROZEN(op)                                            \
	do {                                                                   \
		int status, pipe_fds[2];                                       \
		char started;                                                  \
		TEST_SUCC(pipe(pipe_fds));                                     \
		TEST_SUCC(ioctl(mount_fd, FIFREEZE, 0));                       \
		pid_t pid = TEST_SUCC(fork());                                 \
		if (pid == 0) {                                                \
			close(pipe_fds[0]);                                    \
			if (write(pipe_fds[1], "s", 1) != 1)                   \
				_exit(2);                                      \
			_exit((op) < 0 ? 1 : 0);                               \
		}                                                              \
		TEST_SUCC(close(pipe_fds[1]));                                 \
		TEST_RES(read(pipe_fds[0], &started, 1), _ret == 1);           \
		TEST_SUCC(close(pipe_fds[0]));                                 \
		/* Let `op` reach the gate, or finish if it is ungated. */     \
		usleep(200 * 1000);                                            \
		TEST_RES(waitpid(pid, &status, WNOHANG), _ret == 0);           \
		TEST_SUCC(ioctl(mount_fd, FITHAW, 0));                         \
		TEST_RES(waitpid(pid, &status, 0),                             \
			 _ret == pid && WIFEXITED(status) &&                   \
				 WEXITSTATUS(status) == 0);                    \
	} while (0)

static int write_file(void)
{
	int fd = open(FILE_PATH, O_WRONLY);

	if (fd < 0 || write(fd, "x", 1) != 1)
		return -1;
	return close(fd);
}

FN_TEST(writes_wait_while_frozen)
{
	TEST_WAITS_WHILE_FROZEN(write_file());
	TEST_WAITS_WHILE_FROZEN(mkdir(DIR_PATH, 0755));
	TEST_WAITS_WHILE_FROZEN(rmdir(DIR_PATH));
	TEST_WAITS_WHILE_FROZEN(chmod(FILE_PATH, 0600));
	TEST_WAITS_WHILE_FROZEN(truncate(FILE_PATH, 0));
}
END_TEST()

FN_TEST(reads_and_opens_proceed_while_frozen)
{
	char buf[1];
	int fd;

	TEST_SUCC(ioctl(mount_fd, FIFREEZE, 0));
	/* Opening for writing does not write; only the writes through the file wait. */
	fd = TEST_SUCC(open(FILE_PATH, O_RDWR));
	TEST_SUCC(read(fd, buf, sizeof(buf)));
	TEST_SUCC(close(fd));
	TEST_SUCC(syncfs(mount_fd));
	TEST_SUCC(ioctl(mount_fd, FITHAW, 0));
}
END_TEST()

FN_TEST(tmpfs_cannot_be_frozen)
{
	int fd;

	TEST_SUCC(mount("tmpfs", TMPFS_DIR, "tmpfs", 0, NULL));
	fd = TEST_SUCC(open(TMPFS_DIR, O_RDONLY | O_DIRECTORY));
	TEST_ERRNO(ioctl(fd, FIFREEZE, 0), EOPNOTSUPP);
	TEST_SUCC(close(fd));
	TEST_SUCC(umount(TMPFS_DIR));
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(close(mount_fd));
	CHECK(unlink(FILE_PATH));
	CHECK(umount_block_device(MOUNT_DIR));
	CHECK(close_block_device(block_device_fd));
	CHECK(rmdir(MOUNT_DIR));
	CHECK(rmdir(TMPFS_DIR));
}
END_SETUP()
