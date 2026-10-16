// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"
#include "../../common/block_device.h"

#define MOUNT_DIR "/tmp/atime"
#define FILE_PATH MOUNT_DIR "/file"

static int block_device_fd;

FN_SETUP(prepare)
{
	CHECK_WITH(mkdir(MOUNT_DIR, 0755), _ret >= 0 || errno == EEXIST);
	CHECK(unshare(CLONE_NEWNS));
	block_device_fd = CHECK(open_block_device(BLOCK_VDC_EXT2));
	CHECK(mount_block_device(block_device_fd, MOUNT_DIR, "ext2", 0));
	int fd = CHECK(open(FILE_PATH, O_CREAT | O_TRUNC | O_WRONLY, 0644));
	CHECK(write(fd, "data", 4));
	CHECK(close(fd));
}
END_SETUP()

/* Sets the access and modification times to the given seconds. */
static int set_times(time_t atime, time_t mtime)
{
	struct timespec times[2] = { { .tv_sec = atime }, { .tv_sec = mtime } };

	return utimensat(AT_FDCWD, FILE_PATH, times, 0);
}

/* Reads the file once with `flags` and returns its access time in seconds. */
static time_t read_and_get_atime(int flags)
{
	char buf[4];
	struct stat st;
	int fd = CHECK(open(FILE_PATH, O_RDONLY | flags));

	CHECK(read(fd, buf, sizeof(buf)));
	CHECK(close(fd));
	CHECK(stat(FILE_PATH, &st));
	return st.st_atim.tv_sec;
}

static int remount(unsigned long flags)
{
	return mount(NULL, MOUNT_DIR, NULL, MS_REMOUNT | MS_BIND | flags, NULL);
}

FN_TEST(relatime_updates_only_stale_atime)
{
	TEST_SUCC(remount(MS_RELATIME));

	/* An access time older than the last modification is updated. */
	TEST_SUCC(set_times(1000, 2000));
	TEST_RES(read_and_get_atime(0), _ret > 2000);

	/*
	 * An access time newer than the last change, which `utimensat` sets to now, and less
	 * than a day old is kept.
	 */
	time_t now = time(NULL);
	TEST_SUCC(set_times(now + 60, 2000));
	TEST_RES(read_and_get_atime(0), _ret == now + 60);

	/* An access time older than a day is updated. */
	TEST_SUCC(set_times(now - 2 * 24 * 60 * 60, 2000));
	TEST_RES(read_and_get_atime(0), _ret >= now);
}
END_TEST()

FN_TEST(strictatime_always_updates)
{
	TEST_SUCC(remount(MS_STRICTATIME));
	time_t now = time(NULL);
	TEST_SUCC(set_times(now - 10, 2000));
	TEST_RES(read_and_get_atime(0), _ret >= now);
}
END_TEST()

FN_TEST(noatime_and_o_noatime_never_update)
{
	TEST_SUCC(remount(MS_STRICTATIME));
	TEST_SUCC(set_times(1000, 2000));
	TEST_RES(read_and_get_atime(O_NOATIME), _ret == 1000);

	TEST_SUCC(remount(MS_NOATIME));
	TEST_RES(read_and_get_atime(0), _ret == 1000);
}
END_TEST()

FN_TEST(read_only_mount_does_not_update)
{
	TEST_SUCC(remount(MS_STRICTATIME));
	TEST_SUCC(set_times(1000, 2000));
	TEST_SUCC(remount(MS_RDONLY | MS_STRICTATIME));
	TEST_RES(read_and_get_atime(0), _ret == 1000);
	TEST_SUCC(remount(MS_STRICTATIME));
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(unlink(FILE_PATH));
	CHECK(umount_block_device(MOUNT_DIR));
	CHECK(close_block_device(block_device_fd));
	CHECK(rmdir(MOUNT_DIR));
}
END_SETUP()
