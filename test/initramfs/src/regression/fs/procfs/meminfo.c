// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../../common/test.h"

#define MEMINFO_PATH "/proc/meminfo"
#define BUF_SIZE 16384

#define KB 1024L
#define MB (1024L * KB)

// Linux updates the global page counters from per-CPU deltas lazily. The
// tolerance covers the deltas and the noise from other processes.
#define TOLERANCE_KB (16 * MB / KB)

static char meminfo_buf[BUF_SIZE];

static const char *read_meminfo(void)
{
	int fd = CHECK(open(MEMINFO_PATH, O_RDONLY));
	size_t len = 0;
	ssize_t nread;

	while ((nread = CHECK(read(fd, meminfo_buf + len,
				   sizeof(meminfo_buf) - 1 - len))) > 0)
		len += nread;
	CHECK(close(fd));
	meminfo_buf[len] = '\0';

	return meminfo_buf;
}

// Returns the value of the field in kB (or in pages for `HugePages_*`), or -1
// if the field does not exist.
static long field_in(const char *buf, const char *name)
{
	size_t name_len = strlen(name);
	const char *line = buf;

	while (*line != '\0') {
		if (strncmp(line, name, name_len) == 0 &&
		    line[name_len] == ':')
			return strtol(line + name_len + 1, NULL, 10);

		line = strchr(line, '\n');
		if (line == NULL)
			break;
		line++;
	}

	return -1;
}

static long field(const char *name)
{
	return field_in(read_meminfo(), name);
}

// Waits until `field(name)` satisfies `cond` with `_val` as the value.
#define WAIT_FIELD(name, cond)                                \
	({                                                    \
		long _val;                                    \
		for (int _i = 0; _i < 50; ++_i) {             \
			_val = field(name);                   \
			if (cond)                             \
				break;                        \
			usleep(100 * 1000);                   \
		}                                             \
		_val;                                         \
	})

// Checks the line follows Linux's `show_val_kb` layout: the name and the colon
// are padded to 16 characters, and the value is right-aligned to 8 characters.
static int is_line_well_formed(const char *line, size_t len)
{
	const char *colon = memchr(line, ':', len);
	if (colon == NULL || colon == line)
		return 0;
	for (const char *p = line; p < colon; ++p) {
		if (!isalnum((unsigned char)*p) && *p != '_' && *p != '(' &&
		    *p != ')')
			return 0;
	}

	const char *p = colon + 1;
	while (p < line + len && *p == ' ')
		p++;
	const char *digits = p;
	while (p < line + len && isdigit((unsigned char)*p))
		p++;
	size_t nr_digits = p - digits;
	if (nr_digits == 0)
		return 0;

	size_t rest = line + len - p;
	if (!(rest == 0 || (rest == 3 && memcmp(p, " kB", 3) == 0)))
		return 0;

	size_t label_len = colon + 1 - line;
	if (label_len < 16)
		label_len = 16;
	else
		label_len++;
	size_t value_end = label_len + nr_digits;
	if (value_end < 24)
		value_end = 24;

	return (size_t)(p - line) == value_end;
}

static int count_malformed_lines(const char *buf)
{
	int nr_malformed = 0;

	for (const char *line = buf; *line != '\0';) {
		const char *end = strchr(line, '\n');
		if (end == NULL)
			return nr_malformed + 1;

		size_t len = end - line;
		if (!is_line_well_formed(line, len)) {
			fprintf(stderr, "malformed line: %.*s\n", (int)len,
				line);
			nr_malformed++;
		}
		line = end + 1;
	}

	return nr_malformed;
}

FN_TEST(line_format)
{
	const char *buf = read_meminfo();

	TEST_RES(strlen(buf), _ret > 0 && buf[_ret - 1] == '\n');
	TEST_RES(count_malformed_lines(buf), _ret == 0);
}
END_TEST()

// The fields that Linux prints unconditionally, in Linux's order.
static const char *required_fields[] = {
	"MemTotal",	  "MemFree",	    "MemAvailable", "Buffers",
	"Cached",	  "SwapCached",	    "Active",	    "Inactive",
	"Active(anon)",	  "Inactive(anon)", "Active(file)", "Inactive(file)",
	"Unevictable",	  "Mlocked",	    "SwapTotal",    "SwapFree",
	"Dirty",	  "Writeback",	    "AnonPages",    "Mapped",
	"Shmem",	  "KReclaimable",   "Slab",	    "SReclaimable",
	"SUnreclaim",	  "KernelStack",    "PageTables",   "SecPageTables",
	"NFS_Unstable",	  "Bounce",	    "WritebackTmp", "CommitLimit",
	"Committed_AS",	  "VmallocTotal",   "VmallocUsed",  "VmallocChunk",
	"Percpu",
};

static int count_missing_fields(const char *buf)
{
	const char *pos = buf;
	int nr_missing = 0;

	for (size_t i = 0;
	     i < sizeof(required_fields) / sizeof(required_fields[0]); ++i) {
		char needle[64];
		snprintf(needle, sizeof(needle), "%s:", required_fields[i]);

		// Search for the field from the end of the previous field.
		const char *found = pos;
		while ((found = strstr(found, needle)) != NULL &&
		       found != buf && found[-1] != '\n')
			found++;

		if (found == NULL) {
			fprintf(stderr, "missing or misplaced field: %s\n",
				required_fields[i]);
			nr_missing++;
		} else {
			pos = found + 1;
		}
	}

	return nr_missing;
}

FN_TEST(required_fields_in_order)
{
	TEST_RES(count_missing_fields(read_meminfo()), _ret == 0);
}
END_TEST()

FN_TEST(invariants)
{
	const char *buf = read_meminfo();

	long total = field_in(buf, "MemTotal");
	TEST_RES(total, _ret > 0);
	TEST_RES(field_in(buf, "MemFree"), _ret >= 0 && _ret <= total);
	TEST_RES(field_in(buf, "MemAvailable"), _ret >= 0 && _ret <= total);
	TEST_RES(field_in(buf, "SwapFree"),
		 _ret <= field_in(buf, "SwapTotal"));

	TEST_RES(field_in(buf, "Active"),
		 _ret == field_in(buf, "Active(anon)") +
				 field_in(buf, "Active(file)"));
	TEST_RES(field_in(buf, "Inactive"),
		 _ret == field_in(buf, "Inactive(anon)") +
				 field_in(buf, "Inactive(file)"));
	TEST_RES(field_in(buf, "Slab"),
		 _ret > 0 && _ret == field_in(buf, "SReclaimable") +
					     field_in(buf, "SUnreclaim"));
	TEST_RES(field_in(buf, "Shmem"),
		 _ret <= field_in(buf, "Cached") + field_in(buf, "SwapCached"));

	TEST_RES(field_in(buf, "KernelStack"), _ret > 0);
	TEST_RES(field_in(buf, "PageTables"), _ret > 0);
	TEST_RES(field_in(buf, "CommitLimit"), _ret > 0);
	TEST_RES(field_in(buf, "Committed_AS"), _ret > 0);
	TEST_RES(field_in(buf, "VmallocTotal"), _ret > 0);
	TEST_RES(field_in(buf, "VmallocUsed"), _ret > 0);
	TEST_RES(field_in(buf, "Percpu"), _ret > 0);
	TEST_RES(field_in(buf, "NFS_Unstable"), _ret == 0);
	TEST_RES(field_in(buf, "Bounce"), _ret == 0);
	TEST_RES(field_in(buf, "WritebackTmp"), _ret == 0);
	TEST_RES(field_in(buf, "VmallocChunk"), _ret == 0);
}
END_TEST()

static const char *env_or(const char *name, const char *dflt)
{
	const char *val = getenv(name);
	return val != NULL ? val : dflt;
}

static void write_file(int fd, long size)
{
	static char chunk[MB];
	memset(chunk, 0x5a, sizeof(chunk));

	for (long written = 0; written < size; written += sizeof(chunk))
		CHECK_WITH(write(fd, chunk, sizeof(chunk)),
			   _ret == sizeof(chunk));
}

#define FILE_SIZE (64 * MB)
#define FILE_SIZE_KB (FILE_SIZE / KB)

FN_TEST(shmem_and_cached)
{
	char path[256];
	snprintf(path, sizeof(path), "%s/meminfo_shmem",
		 env_or("MEMINFO_TMPFS_DIR", "/dev/shm"));

	long shmem = field("Shmem");
	long cached = field("Cached");

	int fd = TEST_SUCC(open(path, O_CREAT | O_TRUNC | O_RDWR, 0600));
	write_file(fd, FILE_SIZE);

	TEST_RES(WAIT_FIELD("Shmem",
			    _val >= shmem + FILE_SIZE_KB - TOLERANCE_KB),
		 _ret >= shmem + FILE_SIZE_KB - TOLERANCE_KB);
	TEST_RES(WAIT_FIELD("Cached",
			    _val >= cached + FILE_SIZE_KB - TOLERANCE_KB),
		 _ret >= cached + FILE_SIZE_KB - TOLERANCE_KB);

	// Mapping and touching the file data counts them as mapped.
	long mapped = field("Mapped");
	char *addr = TEST_SUCC(
		mmap(NULL, FILE_SIZE, PROT_READ, MAP_SHARED, fd, 0));
	for (long off = 0; off < FILE_SIZE; off += 4096)
		(void)*(volatile char *)(addr + off);
	TEST_RES(WAIT_FIELD("Mapped",
			    _val >= mapped + FILE_SIZE_KB - TOLERANCE_KB),
		 _ret >= mapped + FILE_SIZE_KB - TOLERANCE_KB);
	TEST_SUCC(munmap(addr, FILE_SIZE));
	TEST_RES(WAIT_FIELD("Mapped", _val <= mapped + TOLERANCE_KB),
		 _ret <= mapped + TOLERANCE_KB);

	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(path));

	TEST_RES(WAIT_FIELD("Shmem", _val <= shmem + TOLERANCE_KB),
		 _ret <= shmem + TOLERANCE_KB);
}
END_TEST()

FN_TEST(dirty_and_fsync)
{
	char path[256];
	snprintf(path, sizeof(path), "%s/meminfo_dirty",
		 env_or("MEMINFO_DISK_DIR", "/ext2"));

	long cached = field("Cached");
	long dirty = field("Dirty");

	int fd = TEST_SUCC(open(path, O_CREAT | O_TRUNC | O_RDWR, 0600));
	write_file(fd, FILE_SIZE);

	TEST_RES(WAIT_FIELD("Cached",
			    _val >= cached + FILE_SIZE_KB - TOLERANCE_KB),
		 _ret >= cached + FILE_SIZE_KB - TOLERANCE_KB);
	long dirty_after_write = TEST_RES(
		WAIT_FIELD("Dirty",
			   _val >= dirty + FILE_SIZE_KB - TOLERANCE_KB),
		_ret >= dirty + FILE_SIZE_KB - TOLERANCE_KB);

	TEST_SUCC(fsync(fd));
	TEST_RES(WAIT_FIELD("Dirty", _val <= dirty_after_write -
						     FILE_SIZE_KB +
						     TOLERANCE_KB),
		 _ret <= dirty_after_write - FILE_SIZE_KB + TOLERANCE_KB);

	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(path));
}
END_TEST()

#define ANON_SIZE (64 * MB)
#define ANON_SIZE_KB (ANON_SIZE / KB)

FN_TEST(anon_pages)
{
	long anon = field("AnonPages");

	char *addr = TEST_SUCC(mmap(NULL, ANON_SIZE, PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
	for (long off = 0; off < ANON_SIZE; off += 4096)
		addr[off] = 1;

	long anon_touched = TEST_RES(
		WAIT_FIELD("AnonPages",
			   _val >= anon + ANON_SIZE_KB - TOLERANCE_KB),
		_ret >= anon + ANON_SIZE_KB - TOLERANCE_KB);

	TEST_SUCC(munmap(addr, ANON_SIZE));
	TEST_RES(WAIT_FIELD("AnonPages", _val <= anon_touched - ANON_SIZE_KB +
							 TOLERANCE_KB),
		 _ret <= anon_touched - ANON_SIZE_KB + TOLERANCE_KB);
}
END_TEST()

#define COMMIT_SIZE (1024 * MB)
#define COMMIT_SIZE_KB (COMMIT_SIZE / KB)
#define COMMIT_TOLERANCE_KB (256 * MB / KB)

FN_TEST(committed_as)
{
	long committed = field("Committed_AS");

	// Private writable mappings are charged when they are created.
	void *addr = TEST_SUCC(mmap(NULL, COMMIT_SIZE, PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
	TEST_RES(field("Committed_AS"),
		 _ret >= committed + COMMIT_SIZE_KB - COMMIT_TOLERANCE_KB);
	TEST_SUCC(munmap(addr, COMMIT_SIZE));
	TEST_RES(field("Committed_AS"),
		 _ret <= committed + COMMIT_TOLERANCE_KB);

	// `MAP_NORESERVE` mappings are not charged.
	addr = TEST_SUCC(mmap(NULL, COMMIT_SIZE, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1,
			      0));
	TEST_RES(field("Committed_AS"),
		 _ret <= committed + COMMIT_TOLERANCE_KB);
	TEST_SUCC(munmap(addr, COMMIT_SIZE));

	// Read-only mappings are charged when they become writable.
	addr = TEST_SUCC(mmap(NULL, COMMIT_SIZE, PROT_READ,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
	TEST_RES(field("Committed_AS"),
		 _ret <= committed + COMMIT_TOLERANCE_KB);
	TEST_SUCC(mprotect(addr, COMMIT_SIZE, PROT_READ | PROT_WRITE));
	TEST_RES(field("Committed_AS"),
		 _ret >= committed + COMMIT_SIZE_KB - COMMIT_TOLERANCE_KB);
	TEST_SUCC(munmap(addr, COMMIT_SIZE));

	// Shared anonymous mappings are charged as a whole.
	addr = TEST_SUCC(mmap(NULL, COMMIT_SIZE, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_ANONYMOUS, -1, 0));
	TEST_RES(field("Committed_AS"),
		 _ret >= committed + COMMIT_SIZE_KB - COMMIT_TOLERANCE_KB);
	TEST_SUCC(munmap(addr, COMMIT_SIZE));
	TEST_RES(field("Committed_AS"),
		 _ret <= committed + COMMIT_TOLERANCE_KB);
}
END_TEST()

#define NR_THREADS 16

static int thread_pipe[2];

static void *blocked_thread(void *arg)
{
	char c;
	(void)arg;
	CHECK(read(thread_pipe[0], &c, 1));
	return NULL;
}

FN_TEST(kernel_stack)
{
	pthread_t threads[NR_THREADS];

	long stack = field("KernelStack");

	TEST_SUCC(pipe(thread_pipe));
	for (int i = 0; i < NR_THREADS; ++i)
		TEST_RES(pthread_create(&threads[i], NULL, blocked_thread,
					NULL),
			 _ret == 0);

	// Each thread has at least an 8 KiB kernel stack.
	TEST_RES(field("KernelStack"), _ret >= stack + NR_THREADS * 8);

	char buf[NR_THREADS] = { 0 };
	TEST_RES(write(thread_pipe[1], buf, sizeof(buf)),
		 _ret == sizeof(buf));
	for (int i = 0; i < NR_THREADS; ++i)
		TEST_RES(pthread_join(threads[i], NULL), _ret == 0);
	TEST_SUCC(close(thread_pipe[0]));
	TEST_SUCC(close(thread_pipe[1]));
}
END_TEST()

#define SPARSE_SIZE (512 * MB)
#define HUGE_PAGE_SIZE (2 * MB)

FN_TEST(page_tables)
{
	long page_tables = field("PageTables");

	char *addr = TEST_SUCC(mmap(NULL, SPARSE_SIZE, PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
	// Avoid huge pages, which need no last-level page tables.
	madvise(addr, SPARSE_SIZE, MADV_NOHUGEPAGE);

	// Each touched 2 MiB region needs a last-level page table.
	for (long off = 0; off < SPARSE_SIZE; off += HUGE_PAGE_SIZE)
		addr[off] = 1;
	long nr_tables_kb = SPARSE_SIZE / HUGE_PAGE_SIZE * 4;
	TEST_RES(field("PageTables"), _ret >= page_tables + nr_tables_kb / 2);

	TEST_SUCC(munmap(addr, SPARSE_SIZE));
}
END_TEST()
