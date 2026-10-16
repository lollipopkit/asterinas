// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "../../common/test.h"
#include "../../common/block_device.h"

#define MOUNT_DIR "/tmp/readonly_mount"
#define FILE_PATH MOUNT_DIR "/file"
#define FIFO_PATH MOUNT_DIR "/fifo"
#define NEW_PATH MOUNT_DIR "/new"
#define XATTR_NAME "user.readonly_mount"

static int block_device_fd;

FN_SETUP(prepare)
{
	CHECK_WITH(mkdir(MOUNT_DIR, 0755), _ret >= 0 || errno == EEXIST);
	CHECK(unshare(CLONE_NEWNS));
	block_device_fd = CHECK(open_block_device(BLOCK_VDC_EXT2));

	CHECK(mount_block_device(block_device_fd, MOUNT_DIR, "ext2", 0));
	CHECK_WITH(unlink(FILE_PATH), _ret == 0 || errno == ENOENT);
	CHECK_WITH(unlink(FIFO_PATH), _ret == 0 || errno == ENOENT);
	CHECK(close(CHECK(open(FILE_PATH, O_CREAT | O_WRONLY, 0644))));
	CHECK(mkfifo(FIFO_PATH, 0644));
	CHECK(setxattr(FILE_PATH, XATTR_NAME, "1", 1, 0));
	CHECK(umount_block_device(MOUNT_DIR));
}
END_SETUP()

/* Expands inside an `FN_TEST`, which provides the test counters. */
#define CHECK_WRITES_FAIL_WITH_EROFS()                                         \
	do {                                                                   \
		int fd;                                                        \
		TEST_ERRNO(open(FILE_PATH, O_WRONLY), EROFS);                  \
		TEST_ERRNO(open(FILE_PATH, O_RDWR), EROFS);                    \
		TEST_ERRNO(open(FILE_PATH, O_RDONLY | O_TRUNC), EROFS);        \
		TEST_ERRNO(open(NEW_PATH, O_CREAT | O_WRONLY, 0644), EROFS);   \
		TEST_ERRNO(truncate(FILE_PATH, 0), EROFS);                     \
		TEST_ERRNO(chmod(FILE_PATH, 0600), EROFS);                     \
		TEST_ERRNO(chown(FILE_PATH, 1, 1), EROFS);                     \
		TEST_ERRNO(utimensat(AT_FDCWD, FILE_PATH, NULL, 0), EROFS);    \
		TEST_ERRNO(setxattr(FILE_PATH, XATTR_NAME, "2", 1, 0), EROFS); \
		TEST_ERRNO(removexattr(FILE_PATH, XATTR_NAME), EROFS);         \
		TEST_ERRNO(access(FILE_PATH, W_OK), EROFS);                    \
		/* Reading still works. */                                     \
		fd = TEST_SUCC(open(FILE_PATH, O_RDONLY));                     \
		TEST_SUCC(close(fd));                                          \
		TEST_SUCC(access(FILE_PATH, R_OK));                            \
		/* Opening a FIFO does not write to the file system. */        \
		fd = TEST_SUCC(open(FIFO_PATH, O_RDWR));                       \
		TEST_SUCC(close(fd));                                          \
		TEST_SUCC(access(FIFO_PATH, W_OK));                            \
	} while (0)

FN_TEST(readonly_filesystem_rejects_writes)
{
	TEST_SUCC(mount_block_device(block_device_fd, MOUNT_DIR, "ext2",
				     MS_RDONLY));
	CHECK_WRITES_FAIL_WITH_EROFS();
	TEST_SUCC(umount_block_device(MOUNT_DIR));
}
END_TEST()

FN_TEST(readonly_bind_mount_rejects_writes)
{
	TEST_SUCC(
		mount_block_device(block_device_fd, MOUNT_DIR, "ext2", 0));
	TEST_SUCC(mount(NULL, MOUNT_DIR, NULL,
			MS_REMOUNT | MS_BIND | MS_RDONLY, NULL));
	CHECK_WRITES_FAIL_WITH_EROFS();
	TEST_SUCC(umount_block_device(MOUNT_DIR));
}
END_TEST()

FN_TEST(remount_readonly_fails_with_writers)
{
	int fd;

	TEST_SUCC(
		mount_block_device(block_device_fd, MOUNT_DIR, "ext2", 0));
	fd = TEST_SUCC(open(FILE_PATH, O_WRONLY));

	/* A file open for writing keeps both the file system and the mount writable. */
	TEST_ERRNO(mount(NULL, MOUNT_DIR, NULL, MS_REMOUNT | MS_RDONLY, NULL),
		   EBUSY);
	TEST_ERRNO(mount(NULL, MOUNT_DIR, NULL,
			 MS_REMOUNT | MS_BIND | MS_RDONLY, NULL),
		   EBUSY);
	TEST_RES(write(fd, "x", 1), _ret == 1);

	TEST_SUCC(close(fd));
	TEST_SUCC(mount(NULL, MOUNT_DIR, NULL, MS_REMOUNT | MS_RDONLY, NULL));
	TEST_ERRNO(open(FILE_PATH, O_WRONLY), EROFS);
	TEST_SUCC(umount_block_device(MOUNT_DIR));
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(mount_block_device(block_device_fd, MOUNT_DIR, "ext2", 0));
	CHECK(unlink(FILE_PATH));
	CHECK(unlink(FIFO_PATH));
	CHECK(umount_block_device(MOUNT_DIR));
	CHECK(close_block_device(block_device_fd));
	CHECK(rmdir(MOUNT_DIR));
}
END_SETUP()
