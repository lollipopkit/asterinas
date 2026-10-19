// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../../common/test.h"

#define PAGE_SIZE 4096
#define PAGE_KB (PAGE_SIZE / 1024)

// Linux updates the global page counters from per-CPU deltas lazily, and
// other processes allocate memory concurrently. Asterinas counts exactly, but
// the kernel itself may still allocate a few pages (e.g., for page tables).
#ifdef __asterinas__
#define TOLERANCE_KB 256L
#else
#define TOLERANCE_KB (16L * 1024)
#endif

// Returns the value of the field in kB from a `/proc` file like
// `/proc/meminfo` or `/proc/self/status`.
static long field_kb(const char *path, const char *name)
{
	FILE *file = fopen(path, "r");
	if (file == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	char line[256];
	size_t name_len = strlen(name);
	long value = -1;
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strncmp(line, name, name_len) == 0 &&
		    line[name_len] == ':') {
			value = strtol(line + name_len + 1, NULL, 10);
			break;
		}
	}
	fclose(file);

	if (value < 0) {
		fprintf(stderr, "cannot find %s in %s\n", name, path);
		exit(EXIT_FAILURE);
	}
	return value;
}

// Linux's per-process RSS counters are per-CPU counters, which are read
// approximately.
//
// Reference: <https://elixir.bootlin.com/linux/v7.2.10/source/lib/percpu_counter.c#L255-L264>
static long rss_tolerance_kb(void)
{
#ifdef __asterinas__
	return 64;
#else
	long batch = CHECK(sysconf(_SC_NPROCESSORS_ONLN)) * 2;
	if (batch < 32)
		batch = 32;
	// Anonymous and file pages are counted in separate counters.
	return batch * 2 * PAGE_KB;
#endif
}

static long meminfo_kb(const char *name)
{
	return field_kb("/proc/meminfo", name);
}

static long status_kb(const char *name)
{
	return field_kb("/proc/self/status", name);
}

#define NR_THREADS 64

// Linux uses 16 KiB kernel stacks on x86-64 (`THREAD_SIZE`). Asterinas also
// runs IRQs on kernel stacks and needs larger ones in debug builds, but a
// kernel stack must not cost hundreds of KiB.
#if defined(__asterinas__) && !defined(__x86_64__)
// The kernel stacks of other architectures are not reduced yet.
#define MAX_KERNEL_STACK_KB 256L
#else
#define MAX_KERNEL_STACK_KB 128L
#endif

// The memory of a blocked thread is mostly its kernel stack, its task
// structures, and a few touched pages of its user stack.
#define MAX_THREAD_KB (MAX_KERNEL_STACK_KB + 64L)

static int block_pipe[2];
static int ready_pipe[2];

static void *blocked_thread(void *arg)
{
	char c = 0;
	(void)arg;
	CHECK(write(ready_pipe[1], &c, 1));
	CHECK(read(block_pipe[0], &c, 1));
	return NULL;
}

FN_TEST(thread_memory)
{
	pthread_t threads[NR_THREADS];
	char buf[NR_THREADS] = { 0 };

	TEST_SUCC(pipe(block_pipe));
	TEST_SUCC(pipe(ready_pipe));

	// Fault in the pages used to read the counters.
	meminfo_kb("MemFree");
	long kernel_stack = meminfo_kb("KernelStack");
	long mem_free = meminfo_kb("MemFree");

	for (int i = 0; i < NR_THREADS; ++i)
		TEST_RES(pthread_create(&threads[i], NULL, blocked_thread,
					NULL),
			 _ret == 0);
	for (int i = 0; i < NR_THREADS; ++i)
		TEST_RES(read(ready_pipe[0], buf, 1), _ret == 1);

	long kernel_stack_delta = meminfo_kb("KernelStack") - kernel_stack;
	long mem_free_delta = mem_free - meminfo_kb("MemFree");
	fprintf(stderr, "%d threads: KernelStack +%ld kB, MemFree -%ld kB\n",
		NR_THREADS, kernel_stack_delta, mem_free_delta);

	TEST_RES(kernel_stack_delta,
		 _ret >= NR_THREADS * 8 &&
			 _ret <= NR_THREADS * MAX_KERNEL_STACK_KB);
	TEST_RES(mem_free_delta,
		 _ret <= NR_THREADS * MAX_THREAD_KB + TOLERANCE_KB);

	TEST_RES(write(block_pipe[1], buf, sizeof(buf)), _ret == sizeof(buf));
	for (int i = 0; i < NR_THREADS; ++i)
		TEST_RES(pthread_join(threads[i], NULL), _ret == 0);
	TEST_SUCC(close(block_pipe[0]));
	TEST_SUCC(close(block_pipe[1]));
	TEST_SUCC(close(ready_pipe[0]));
	TEST_SUCC(close(ready_pipe[1]));
}
END_TEST()

// 6 MiB of the 8 MiB stack of the main thread.
#define NR_STACK_PAGES 1536
#define STACK_KB (NR_STACK_PAGES * PAGE_KB)

__attribute__((noinline)) static int touch_stack(void)
{
	volatile char buf[NR_STACK_PAGES * PAGE_SIZE];

	// Touch the pages downwards, as the stack grows.
	for (long i = NR_STACK_PAGES - 1; i >= 0; --i)
		buf[i * PAGE_SIZE] = 1;

	return buf[0];
}

FN_TEST(init_stack_pages)
{
	// Fault in the pages used to read the counters.
	status_kb("RssAnon");
	meminfo_kb("MemFree");
	long rss_anon = status_kb("RssAnon");
	long anon_pages = meminfo_kb("AnonPages");
	long mem_free = meminfo_kb("MemFree");

	TEST_RES(touch_stack(), _ret == 1);

	long rss_anon_delta = status_kb("RssAnon") - rss_anon;
	long anon_pages_delta = meminfo_kb("AnonPages") - anon_pages;
	long mem_free_delta = mem_free - meminfo_kb("MemFree");
	fprintf(stderr,
		"%d stack pages: RssAnon +%ld kB, AnonPages +%ld kB, MemFree -%ld kB\n",
		NR_STACK_PAGES, rss_anon_delta, anon_pages_delta,
		mem_free_delta);

	// Each touched stack page is a single anonymous page.
	TEST_RES(rss_anon_delta, labs(_ret - STACK_KB) <= rss_tolerance_kb());
	TEST_RES(anon_pages_delta, labs(_ret - STACK_KB) <= TOLERANCE_KB);
	TEST_RES(mem_free_delta, _ret <= STACK_KB + TOLERANCE_KB);
}
END_TEST()

// Returns the start address of the `[stack]` mapping.
static unsigned long stack_start(void)
{
	FILE *file = fopen("/proc/self/maps", "r");
	if (file == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	char line[512];
	unsigned long start = 0;
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strstr(line, "[stack]") != NULL) {
			start = strtoul(line, NULL, 16);
			break;
		}
	}
	fclose(file);

	return start;
}

FN_TEST(stack_not_merged)
{
	unsigned long start = TEST_RES(stack_start(), _ret != 0);

	// Like Linux, an adjacent anonymous mapping with the same permissions is
	// not merged into the stack.
	char *below = (char *)start - PAGE_SIZE;
	TEST_RES(mmap(below, PAGE_SIZE, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0),
		 _ret == below);
	TEST_RES(stack_start(), _ret == start);
	TEST_SUCC(munmap(below, PAGE_SIZE));
}
END_TEST()
