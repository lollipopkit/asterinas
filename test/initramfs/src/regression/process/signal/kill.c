// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "../../common/test.h"

FN_SETUP(setpgrp)
{
	CHECK(setpgrp());
}
END_SETUP()

FN_TEST(kill_dead_process)
{
	pid_t ppid, cpid;
	int status;

	ppid = TEST_SUCC(getpid());
	cpid = TEST_SUCC(fork());
	if (cpid == 0) {
		exit(EXIT_SUCCESS);
	}
	usleep(200 * 1000);

	TEST_SUCC(kill(ppid, SIGCHLD));
	TEST_SUCC(kill(-ppid, SIGCHLD));

	// Killing dead processes will succeed.
	TEST_SUCC(kill(cpid, SIGCHLD));
	TEST_ERRNO(kill(-cpid, SIGCHLD), ESRCH);

	TEST_RES(wait(&status),
		 _ret == cpid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()

FN_TEST(kill_dead_group)
{
	pid_t ppid, cpid;
	int status;

	ppid = TEST_SUCC(getpid());
	cpid = TEST_SUCC(fork());
	if (cpid == 0) {
		CHECK(setpgrp());
		exit(EXIT_SUCCESS);
	}
	usleep(200 * 1000);

	TEST_SUCC(kill(ppid, SIGCHLD));
	TEST_SUCC(kill(-ppid, SIGCHLD));

	// Killing dead process groups will succeed.
	TEST_SUCC(kill(cpid, SIGCHLD));
	TEST_SUCC(kill(-cpid, SIGCHLD));

	TEST_RES(wait(&status),
		 _ret == cpid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()

static void *background_thread(void *data)
{
	sleep(3600);
	return NULL;
}

FN_TEST(kill_dead_thread)
{
	pid_t cpid;
	int status;

	cpid = TEST_SUCC(fork());
	if (cpid == 0) {
		pthread_t tid;
		CHECK_WITH(pthread_create(&tid, NULL, background_thread, NULL),
			   _ret == 0);
		syscall(SYS_exit, 0);
	}
	usleep(200 * 1000);

	// Killing dead threads will succeed.
	TEST_SUCC(kill(cpid, SIGCHLD));
	TEST_SUCC(tgkill(cpid, cpid, SIGCHLD));
	TEST_SUCC(syscall(SYS_tkill, cpid, SIGCHLD));

	TEST_SUCC(kill(cpid, SIGKILL));
	TEST_RES(wait(&status), _ret == cpid && WIFSIGNALED(status) &&
					WTERMSIG(status) == SIGKILL);
}
END_TEST()

// A number whose lowest byte is a valid signal number (`SIGUSR1`).
#define BAD_SIG (256 + SIGUSR1)

FN_TEST(invalid_signal_numbers)
{
	pid_t dead_pid, child_pid;
	int pidfd;

	// Get the PID of a reaped process.
	dead_pid = TEST_SUCC(fork());
	if (dead_pid == 0)
		_exit(0);
	TEST_RES(waitpid(dead_pid, NULL, 0), _ret == dead_pid);

	child_pid = TEST_SUCC(fork());
	if (child_pid == 0) {
		pause();
		_exit(0);
	}
	pidfd = TEST_SUCC(syscall(SYS_pidfd_open, child_pid, 0));

	// The target is looked up before the signal number is checked.
	TEST_ERRNO(kill(getpid(), BAD_SIG), EINVAL);
	TEST_ERRNO(kill(getpid(), -1), EINVAL);
	TEST_ERRNO(kill(0, BAD_SIG), EINVAL);
	TEST_ERRNO(kill(child_pid, BAD_SIG), EINVAL);
	TEST_ERRNO(kill(dead_pid, BAD_SIG), ESRCH);
	TEST_ERRNO(kill(-dead_pid, BAD_SIG), ESRCH);

	TEST_ERRNO(syscall(SYS_tgkill, getpid(), gettid(), BAD_SIG), EINVAL);
	TEST_ERRNO(syscall(SYS_tgkill, getpid(), dead_pid, BAD_SIG), ESRCH);
	TEST_ERRNO(syscall(SYS_tgkill, 0, dead_pid, BAD_SIG), EINVAL);
	TEST_ERRNO(syscall(SYS_tkill, gettid(), BAD_SIG), EINVAL);
	TEST_ERRNO(syscall(SYS_tkill, dead_pid, BAD_SIG), ESRCH);

	TEST_ERRNO(syscall(SYS_pidfd_send_signal, pidfd, BAD_SIG, NULL, 0),
		   EINVAL);

	siginfo_t info;
	memset(&info, 0, sizeof(info));
	info.si_code = SI_QUEUE;
	TEST_ERRNO(syscall(SYS_rt_sigqueueinfo, getpid(), BAD_SIG, &info),
		   EINVAL);
	TEST_ERRNO(syscall(SYS_rt_sigqueueinfo, dead_pid, BAD_SIG, &info),
		   ESRCH);
	TEST_ERRNO(syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), BAD_SIG,
			   &info),
		   EINVAL);
	TEST_ERRNO(syscall(SYS_rt_tgsigqueueinfo, getpid(), dead_pid, BAD_SIG,
			   &info),
		   ESRCH);

	// The `si_code` is checked before the target is looked up.
	info.si_code = SI_USER;
	TEST_ERRNO(syscall(SYS_rt_sigqueueinfo, dead_pid, BAD_SIG, &info),
		   EPERM);

	TEST_ERRNO(syscall(SYS_rt_sigaction, BAD_SIG, NULL, NULL, 8), EINVAL);
	TEST_ERRNO(syscall(SYS_rt_sigaction, 0, NULL, NULL, 8), EINVAL);

	int pdeath_sig;
	TEST_ERRNO(prctl(PR_SET_PDEATHSIG, BAD_SIG), EINVAL);
	TEST_ERRNO(prctl(PR_SET_PDEATHSIG, -1), EINVAL);
	TEST_SUCC(prctl(PR_SET_PDEATHSIG, SIGUSR2));
	TEST_RES(prctl(PR_GET_PDEATHSIG, &pdeath_sig), pdeath_sig == SIGUSR2);
	TEST_SUCC(prctl(PR_SET_PDEATHSIG, 0));
	TEST_RES(prctl(PR_GET_PDEATHSIG, &pdeath_sig), pdeath_sig == 0);

	TEST_SUCC(close(pidfd));
	TEST_SUCC(kill(child_pid, SIGKILL));
	TEST_RES(waitpid(child_pid, NULL, 0), _ret == child_pid);
}
END_TEST()
