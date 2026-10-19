// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static long meminfo_kb(const char *name)
{
	return field_kb("/proc/meminfo", name);
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
