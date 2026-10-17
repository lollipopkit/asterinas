// SPDX-License-Identifier: MPL-2.0

/*
 * Tests that threads which never sleep spread over the CPUs after they all start on one CPU.
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"

#define MAX_THREADS 8
#define WINDOW_MS 500

static atomic_int stop;

static void *spin(void *arg)
{
	(void)arg;
	while (!atomic_load(&stop))
		;
	return NULL;
}

static long long thread_cpu_ns(pthread_t thread)
{
	clockid_t clock;
	struct timespec ts;

	CHECK(pthread_getcpuclockid(thread, &clock));
	CHECK(clock_gettime(clock, &ts));
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

FN_TEST(spinning_threads_spread)
{
	cpu_set_t all, first;
	pthread_t threads[MAX_THREADS];
	long long start[MAX_THREADS];
	int nr_threads, i;

	TEST_SUCC(sched_getaffinity(0, sizeof(all), &all));
	nr_threads = CPU_COUNT(&all) < MAX_THREADS ? CPU_COUNT(&all) : MAX_THREADS;
	SKIP_TEST_IF(nr_threads < 2);

	// Start every thread on the first CPU, then allow all CPUs without waking the threads.
	CPU_ZERO(&first);
	for (i = 0; !CPU_ISSET(i, &all); i++)
		;
	CPU_SET(i, &first);
	TEST_SUCC(sched_setaffinity(0, sizeof(first), &first));
	for (i = 0; i < nr_threads; i++)
		TEST_RES(pthread_create(&threads[i], NULL, spin, NULL), _ret == 0);
	for (i = 0; i < nr_threads; i++)
		TEST_RES(pthread_setaffinity_np(threads[i], sizeof(all), &all), _ret == 0);
	TEST_SUCC(sched_setaffinity(0, sizeof(all), &all));

	usleep(200 * 1000);
	for (i = 0; i < nr_threads; i++)
		start[i] = thread_cpu_ns(threads[i]);
	usleep(WINDOW_MS * 1000);
	// Each thread has a CPU of its own, so it runs for most of the window.
	for (i = 0; i < nr_threads; i++)
		TEST_RES(thread_cpu_ns(threads[i]) - start[i], _ret > WINDOW_MS * 700000LL);

	atomic_store(&stop, 1);
	for (i = 0; i < nr_threads; i++)
		TEST_RES(pthread_join(threads[i], NULL), _ret == 0);
}
END_TEST()
