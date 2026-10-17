// SPDX-License-Identifier: MPL-2.0

/*
 * Tests the CPU-time clocks of processes and threads encoded in clock IDs, and the resolution
 * of clocks.
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"

#define CPUCLOCK_PROF 0
#define CPUCLOCK_SCHED 2
#define CPUCLOCK_PERTHREAD_MASK 4
#define MAKE_PROCESS_CPUCLOCK(pid, clock) ((~(clockid_t)(pid) << 3) | (clock))
#define MAKE_THREAD_CPUCLOCK(tid, clock) \
	MAKE_PROCESS_CPUCLOCK(tid, (clock) | CPUCLOCK_PERTHREAD_MASK)

static atomic_int stop;
static atomic_int spinner_tid;

static void *spin(void *arg)
{
	(void)arg;
	atomic_store(&spinner_tid, syscall(SYS_gettid));
	while (!atomic_load(&stop))
		;
	return NULL;
}

/* Reads the process clock named by the TID of the calling thread, which is not the main thread. */
static void *read_by_own_tid(void *arg)
{
	struct timespec ts;

	(void)arg;
	if (clock_gettime(MAKE_PROCESS_CPUCLOCK(syscall(SYS_gettid), CPUCLOCK_SCHED), &ts) < 0)
		return (void *)(long)errno;
	return NULL;
}

static pthread_t spinner;
static pid_t child;

FN_SETUP(spawn)
{
	CHECK_WITH(pthread_create(&spinner, NULL, spin, NULL), _ret == 0);
	while (atomic_load(&spinner_tid) == 0)
		;
	usleep(100 * 1000);

	child = CHECK(fork());
	if (child == 0) {
		pause();
		_exit(0);
	}
}
END_SETUP()

FN_TEST(thread_clock)
{
	struct timespec ts;
	clockid_t clock;

	TEST_RES(pthread_getcpuclockid(spinner, &clock), _ret == 0);
	TEST_RES(clock_gettime(clock, &ts), ts.tv_sec > 0 || ts.tv_nsec > 0);
	TEST_SUCC(clock_gettime(MAKE_THREAD_CPUCLOCK(spinner_tid, CPUCLOCK_PROF), &ts));

	// ID 0 means the current thread.
	TEST_SUCC(clock_gettime(MAKE_THREAD_CPUCLOCK(0, CPUCLOCK_SCHED), &ts));

	// A thread clock only measures a thread in the current process.
	TEST_ERRNO(clock_gettime(MAKE_THREAD_CPUCLOCK(child, CPUCLOCK_SCHED), &ts), EINVAL);
}
END_TEST()

FN_TEST(process_clock)
{
	struct timespec ts;
	clockid_t clock;
	timer_t timer;
	pthread_t reader;
	void *reader_errno;
	struct sigevent sev = { .sigev_notify = SIGEV_NONE };

	TEST_RES(clock_getcpuclockid(0, &clock), _ret == 0);
	TEST_SUCC(clock_gettime(clock, &ts));
	TEST_SUCC(clock_gettime(MAKE_PROCESS_CPUCLOCK(0, CPUCLOCK_SCHED), &ts));
	TEST_RES(clock_getcpuclockid(child, &clock), _ret == 0);
	TEST_SUCC(clock_gettime(clock, &ts));

	// Only `clock_gettime` takes the TID of the current thread for its process.
	TEST_ERRNO(clock_gettime(MAKE_PROCESS_CPUCLOCK(spinner_tid, CPUCLOCK_SCHED), &ts), EINVAL);
	TEST_RES(pthread_create(&reader, NULL, read_by_own_tid, NULL), _ret == 0);
	TEST_RES(pthread_join(reader, &reader_errno), _ret == 0 && reader_errno == NULL);
	TEST_SUCC(timer_create(MAKE_PROCESS_CPUCLOCK(getpid(), CPUCLOCK_SCHED), &sev, &timer));
	TEST_SUCC(timer_delete(timer));
	TEST_ERRNO(timer_create(MAKE_PROCESS_CPUCLOCK(spinner_tid, CPUCLOCK_SCHED), &sev, &timer),
		   EINVAL);
}
END_TEST()

FN_TEST(clock_getres)
{
	struct timespec ts;

	TEST_RES(clock_getres(CLOCK_MONOTONIC, &ts), ts.tv_sec == 0 && ts.tv_nsec > 0);
	TEST_SUCC(clock_getres(CLOCK_REALTIME_COARSE, NULL));
	TEST_RES(clock_getres(MAKE_THREAD_CPUCLOCK(spinner_tid, CPUCLOCK_SCHED), &ts),
		 ts.tv_sec == 0 && ts.tv_nsec > 0);
	TEST_ERRNO(clock_getres(100, &ts), EINVAL);
	TEST_ERRNO(clock_getres(MAKE_THREAD_CPUCLOCK(child, CPUCLOCK_SCHED), &ts), EINVAL);
	// Unlike `clock_gettime`, it does not take the TID of the current thread for its process.
	TEST_ERRNO(clock_getres(MAKE_PROCESS_CPUCLOCK(spinner_tid, CPUCLOCK_SCHED), &ts), EINVAL);
}
END_TEST()

FN_SETUP(cleanup)
{
	atomic_store(&stop, 1);
	CHECK_WITH(pthread_join(spinner, NULL), _ret == 0);
	CHECK(kill(child, SIGKILL));
	CHECK_WITH(waitpid(child, NULL, 0), _ret == child);
}
END_SETUP()
