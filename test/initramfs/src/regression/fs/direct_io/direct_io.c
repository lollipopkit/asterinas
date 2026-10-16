/* SPDX-License-Identifier: MPL-2.0 */

/*
 * Checks that direct I/O reads and writes the file data, in a directory given by
 * `TEST_TMPDIR`.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../common/test.h"

/* Spans several clusters or blocks on every tested file system. */
#define FILE_SIZE (512 * 1024)
#define ALIGNMENT 4096

static char path[PATH_MAX];
static char *expected, *buf;

static void fill(char *data, char seed)
{
	for (size_t i = 0; i < FILE_SIZE; i++)
		data[i] = (char)(seed + i * 7 + i / 4096);
}

FN_SETUP(init)
{
	const char *dir = getenv("TEST_TMPDIR");

	CHECK_WITH(dir != NULL, _ret);
	snprintf(path, sizeof(path), "%s/direct_io_test", dir);
	CHECK_WITH(posix_memalign((void **)&expected, ALIGNMENT, FILE_SIZE),
		   _ret == 0);
	CHECK_WITH(posix_memalign((void **)&buf, ALIGNMENT, FILE_SIZE),
		   _ret == 0);
}
END_SETUP()

FN_TEST(direct_read_sees_buffered_write)
{
	int fd = TEST_SUCC(open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644));

	fill(expected, 1);
	TEST_RES(write(fd, expected, FILE_SIZE), _ret == FILE_SIZE);
	TEST_SUCC(fsync(fd));
	TEST_SUCC(close(fd));

	fd = TEST_SUCC(open(path, O_RDONLY | O_DIRECT));
	memset(buf, 0, FILE_SIZE);
	TEST_RES(read(fd, buf, FILE_SIZE),
		 _ret == FILE_SIZE && memcmp(buf, expected, FILE_SIZE) == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(direct_write_then_read)
{
	int fd = TEST_SUCC(open(path, O_RDWR | O_DIRECT));

	fill(expected, 3);
	TEST_RES(pwrite(fd, expected, FILE_SIZE, 0), _ret == FILE_SIZE);
	memset(buf, 0, FILE_SIZE);
	TEST_RES(pread(fd, buf, FILE_SIZE, 0),
		 _ret == FILE_SIZE && memcmp(buf, expected, FILE_SIZE) == 0);
	TEST_SUCC(close(fd));

	// The data is also seen by buffered I/O.
	fd = TEST_SUCC(open(path, O_RDONLY));
	memset(buf, 0, FILE_SIZE);
	TEST_RES(read(fd, buf, FILE_SIZE),
		 _ret == FILE_SIZE && memcmp(buf, expected, FILE_SIZE) == 0);
	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(path));
}
END_TEST()

FN_TEST(direct_read_stops_at_unaligned_eof)
{
	// The file ends in the middle of a block, and is shorter than the request.
	const size_t file_size = 5000;
	int fd = TEST_SUCC(open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644));

	fill(expected, 5);
	TEST_RES(write(fd, expected, file_size), _ret == file_size);
	TEST_SUCC(fsync(fd));
	TEST_SUCC(close(fd));

	fd = TEST_SUCC(open(path, O_RDONLY | O_DIRECT));
	memset(buf, 0, FILE_SIZE);
	TEST_RES(read(fd, buf, 2 * ALIGNMENT),
		 _ret == file_size && memcmp(buf, expected, file_size) == 0);
	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(path));
}
END_TEST()
