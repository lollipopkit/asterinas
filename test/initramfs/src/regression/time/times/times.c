// SPDX-License-Identifier: MPL-2.0

/*
 * Tests that times(2), `/proc/[pid]/stat`, `/proc/stat`, and `AT_CLKTCK` report clock ticks in
 * `USER_HZ` like Linux.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"

#define USER_HZ 100
#define NSEC_PER_TICK (1000000000L / USER_HZ)

struct pid_stat {
	long utime;
	long stime;
	long cutime;
	long cstime;
	long itrealvalue;
	unsigned long long starttime;
};

static void spin_for(long nsec)
{
	struct timespec start, now;

	CHECK(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start));
	do {
		CHECK(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now));
	} while ((now.tv_sec - start.tv_sec) * 1000000000L +
			 (now.tv_nsec - start.tv_nsec) <
		 nsec);
}

static long cputime_ticks(void)
{
	struct timespec ts;

	CHECK(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts));
	return (ts.tv_sec * 1000000000L + ts.tv_nsec) / NSEC_PER_TICK;
}

static long uptime_ticks(void)
{
	double uptime;
	FILE *file;

	file = CHECK_WITH(fopen("/proc/uptime", "r"), _ret != NULL);
	CHECK_WITH(fscanf(file, "%lf", &uptime), _ret == 1);
	CHECK(fclose(file));
	return (long)(uptime * USER_HZ);
}

static void read_pid_stat(struct pid_stat *stat)
{
	char buf[1024];
	char *fields;
	ssize_t len;
	int fd;

	fd = CHECK(open("/proc/self/stat", O_RDONLY));
	len = CHECK(read(fd, buf, sizeof(buf) - 1));
	CHECK(close(fd));
	buf[len] = '\0';

	// The fields after the command name start from field 3 (`state`).
	fields = CHECK_WITH(strrchr(buf, ')'), _ret != NULL);
	CHECK_WITH(sscanf(fields + 2,
			  "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %ld %ld %ld %ld %*d %*d %*d %ld %llu",
			  &stat->utime, &stat->stime, &stat->cutime, &stat->cstime,
			  &stat->itrealvalue, &stat->starttime),
		   _ret == 6);
}

FN_TEST(clk_tck)
{
	TEST_RES(sysconf(_SC_CLK_TCK), _ret == USER_HZ);
	TEST_RES(getauxval(AT_CLKTCK), _ret == USER_HZ);
}
END_TEST()

FN_TEST(times_self)
{
	struct pid_stat stat;
	struct tms tms;
	long ticks;

	spin_for(300 * 1000 * 1000);

	TEST_SUCC(times(&tms));
	ticks = cputime_ticks();
	TEST_RES(tms.tms_utime + tms.tms_stime,
		 _ret >= 25 && labs(ticks - _ret) <= 3);

	read_pid_stat(&stat);
	TEST_RES(stat.utime + stat.stime,
		 _ret >= tms.tms_utime + tms.tms_stime &&
			 _ret - (tms.tms_utime + tms.tms_stime) <= 3);
}
END_TEST()

FN_TEST(times_children)
{
	struct pid_stat stat;
	struct tms before, after;
	pid_t pid;

	TEST_SUCC(times(&before));

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		spin_for(200 * 1000 * 1000);
		_exit(0);
	}
	TEST_RES(waitpid(pid, NULL, 0), _ret == pid);

	TEST_SUCC(times(&after));
	TEST_RES((after.tms_cutime + after.tms_cstime) -
			 (before.tms_cutime + before.tms_cstime),
		 _ret >= 17 && _ret <= 30);

	read_pid_stat(&stat);
	TEST_RES(stat.cutime + stat.cstime,
		 _ret == after.tms_cutime + after.tms_cstime);
}
END_TEST()

FN_TEST(times_elapsed)
{
	clock_t start, end;

	start = TEST_SUCC(times(NULL));
	usleep(200 * 1000);
	end = TEST_SUCC(times(NULL));
	TEST_RES(end - start, _ret >= 19 && _ret <= 40);

	TEST_ERRNO(syscall(SYS_times, (void *)1), EFAULT);
}
END_TEST()

FN_TEST(pid_stat)
{
	struct pid_stat stat;

	// `itrealvalue` is always zero, even with a pending alarm.
	TEST_RES(alarm(100), _ret == 0);
	read_pid_stat(&stat);
	TEST_RES(stat.itrealvalue, _ret == 0);
	TEST_RES(alarm(0), _ret > 0);

	TEST_RES(stat.starttime, _ret <= (unsigned long long)uptime_ticks());
}
END_TEST()

FN_TEST(proc_stat)
{
	unsigned long long values[10], sum = 0;
	long nprocs;
	FILE *file;
	int i;

	file = TEST_RES(fopen("/proc/stat", "r"), _ret != NULL);
	TEST_RES(fscanf(file,
			"cpu  %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
			&values[0], &values[1], &values[2], &values[3], &values[4],
			&values[5], &values[6], &values[7], &values[8], &values[9]),
		 _ret == 10);
	TEST_SUCC(fclose(file));

	// The guest times are already included in the user times.
	for (i = 0; i < 8; ++i)
		sum += values[i];
	nprocs = TEST_SUCC(sysconf(_SC_NPROCESSORS_CONF));
	TEST_RES(sum, _ret <= (unsigned long long)(uptime_ticks() + USER_HZ) * nprocs);
}
END_TEST()
