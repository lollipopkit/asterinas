// SPDX-License-Identifier: MPL-2.0

// Tests that a failed `MAP_FIXED` mapping leaves the existing mappings intact.

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../../common/test.h"

#define PAGE_SIZE 4096
#define NR_PAGES 3

static int sealed_memfd;
static int other_memfd;
static int read_only_fd;

#define FILE_PATH "mmap_fixed_failure_file"

FN_SETUP(files)
{
	sealed_memfd = CHECK(memfd_create("sealed", MFD_ALLOW_SEALING));
	CHECK(ftruncate(sealed_memfd, NR_PAGES * PAGE_SIZE));
	CHECK(fcntl(sealed_memfd, F_ADD_SEALS, F_SEAL_WRITE));

	other_memfd = CHECK(memfd_create("other", 0));
	CHECK(ftruncate(other_memfd, NR_PAGES * PAGE_SIZE));

	int fd = CHECK(open(FILE_PATH, O_CREAT | O_TRUNC | O_WRONLY, 0600));
	CHECK(ftruncate(fd, NR_PAGES * PAGE_SIZE));
	CHECK(close(fd));
	read_only_fd = CHECK(open(FILE_PATH, O_RDONLY));
	CHECK(unlink(FILE_PATH));
}
END_SETUP()

static void fill_pages(char *addr)
{
	for (int i = 0; i < NR_PAGES; ++i)
		memset(addr + i * PAGE_SIZE, 'a' + i, PAGE_SIZE);
}

// Returns whether all pages still have the content written by `fill_pages`.
static int check_pages(const char *addr)
{
	for (int i = 0; i < NR_PAGES; ++i) {
		for (int j = 0; j < PAGE_SIZE; ++j) {
			if (addr[i * PAGE_SIZE + j] != 'a' + i)
				return 0;
		}
	}
	return 1;
}

// Checks that failed `MAP_FIXED` replacements keep the old mappings at `addr`.
#define TEST_REPLACE_FAILS(addr)                                               \
	do {                                                                   \
		fill_pages(addr);                                              \
                                                                               \
		/* A memfd sealed against writing cannot be mapped writable. */ \
		TEST_ERRNO(mmap(addr + PAGE_SIZE, PAGE_SIZE,                   \
				PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, \
				sealed_memfd, 0),                              \
			   EPERM);                                             \
		TEST_RES(check_pages(addr), _ret);                             \
		TEST_ERRNO(mmap(addr, NR_PAGES * PAGE_SIZE,                    \
				PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, \
				sealed_memfd, 0),                              \
			   EPERM);                                             \
		TEST_RES(check_pages(addr), _ret);                             \
                                                                               \
		/* A read-only file cannot be mapped shared and writable. */   \
		TEST_ERRNO(mmap(addr + PAGE_SIZE, 2 * PAGE_SIZE,               \
				PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, \
				read_only_fd, 0),                              \
			   EACCES);                                            \
		TEST_RES(check_pages(addr), _ret);                             \
                                                                               \
		/* The old mappings are still writable. */                     \
		fill_pages(addr);                                              \
		TEST_RES(check_pages(addr), _ret);                             \
	} while (0)

FN_TEST(replace_private_anonymous)
{
	char *addr = TEST_SUCC(mmap(NULL, NR_PAGES * PAGE_SIZE,
				    PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
	TEST_REPLACE_FAILS(addr);
	TEST_SUCC(munmap(addr, NR_PAGES * PAGE_SIZE));
}
END_TEST()

FN_TEST(replace_shared_anonymous)
{
	char *addr = TEST_SUCC(mmap(NULL, NR_PAGES * PAGE_SIZE,
				    PROT_READ | PROT_WRITE,
				    MAP_SHARED | MAP_ANONYMOUS, -1, 0));
	TEST_REPLACE_FAILS(addr);
	TEST_SUCC(munmap(addr, NR_PAGES * PAGE_SIZE));
}
END_TEST()

FN_TEST(replace_shared_file)
{
	char *addr = TEST_SUCC(mmap(NULL, NR_PAGES * PAGE_SIZE,
				    PROT_READ | PROT_WRITE, MAP_SHARED,
				    other_memfd, 0));
	TEST_REPLACE_FAILS(addr);
	TEST_SUCC(munmap(addr, NR_PAGES * PAGE_SIZE));

	// The writes reach the file.
	addr = TEST_SUCC(mmap(NULL, NR_PAGES * PAGE_SIZE, PROT_READ, MAP_SHARED,
			      other_memfd, 0));
	TEST_RES(check_pages(addr), _ret);
	TEST_SUCC(munmap(addr, NR_PAGES * PAGE_SIZE));
}
END_TEST()

FN_TEST(replace_private_file_cow)
{
	char *addr = TEST_SUCC(mmap(NULL, NR_PAGES * PAGE_SIZE,
				    PROT_READ | PROT_WRITE, MAP_PRIVATE,
				    other_memfd, 0));
	TEST_REPLACE_FAILS(addr);
	TEST_SUCC(munmap(addr, NR_PAGES * PAGE_SIZE));
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(close(sealed_memfd));
	CHECK(close(other_memfd));
	CHECK(close(read_only_fd));
}
END_SETUP()
