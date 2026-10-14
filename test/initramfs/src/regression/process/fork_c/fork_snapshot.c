// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include "../../common/test.h"

// The child of `fork` must see a consistent snapshot of the parent's memory,
// even if other threads of the parent keep writing to memory during the fork.

#define PAGE_SIZE 4096
#define SLOT_STRIDE (PAGE_SIZE / sizeof(unsigned long))
// The number of pages written in turn by the writer. It exceeds the TLB
// capacity so that writes keep page-faulting after the pages become COW.
#define NR_SLOTS 8192
// The number of mappings between the slots and the sequence number. They make
// the fork take longer.
#define NR_FILLERS 2048
#define NR_FORKS 100

static unsigned long *slots;
static unsigned long *seq;
static int stop;

// Writes `i` to slot `i % NR_SLOTS` and then publishes `i` as the sequence
// number. In any consistent snapshot, slot `seq % NR_SLOTS` holds `seq`.
static void *writer(void *arg)
{
	for (unsigned long i = 1; !__atomic_load_n(&stop, __ATOMIC_RELAXED);
	     i++) {
		__atomic_store_n(&slots[(i % NR_SLOTS) * SLOT_STRIDE], i,
				 __ATOMIC_RELAXED);
		__atomic_store_n(seq, i, __ATOMIC_RELEASE);
	}
	return NULL;
}

static int is_consistent(void)
{
	unsigned long s = *seq;

	return s == 0 || slots[(s % NR_SLOTS) * SLOT_STRIDE] == s;
}

FN_SETUP(mappings)
{
	size_t len = (NR_SLOTS + NR_FILLERS + 1) * PAGE_SIZE;
	char *base = CHECK_WITH(mmap(NULL, len, PROT_READ | PROT_WRITE,
				     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
				_ret != MAP_FAILED);
	char *fillers = base + NR_SLOTS * PAGE_SIZE;

	// The slots come before the sequence number, so the fork copies them
	// first.
	slots = (unsigned long *)base;
	seq = (unsigned long *)(fillers + NR_FILLERS * PAGE_SIZE);
	memset(base, 0, len);

	// Split the fillers into separate mappings.
	for (int i = 1; i < NR_FILLERS; i += 2)
		CHECK(mprotect(fillers + i * PAGE_SIZE, PAGE_SIZE, PROT_READ));
}
END_SETUP()

FN_TEST(child_sees_consistent_snapshot)
{
	pthread_t thread;
	int status, nr_inconsistent = 0;

	TEST_SUCC(pthread_create(&thread, NULL, writer, NULL));

	for (int i = 0; i < NR_FORKS; i++) {
		pid_t pid = CHECK(fork());
		if (pid == 0) {
			_exit(is_consistent() ? EXIT_SUCCESS : EXIT_FAILURE);
		}
		CHECK_WITH(waitpid(pid, &status, 0),
			   _ret == pid && WIFEXITED(status));
		if (WEXITSTATUS(status) != EXIT_SUCCESS)
			nr_inconsistent++;
	}
	TEST_RES(nr_inconsistent, _ret == 0);

	__atomic_store_n(&stop, 1, __ATOMIC_RELAXED);
	TEST_SUCC(pthread_join(thread, NULL));
}
END_TEST()
