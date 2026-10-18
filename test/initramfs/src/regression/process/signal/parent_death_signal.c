// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"

// Exit codes of the child that reports what it receives.
#define GOT_PDEATHSIG 10
#define GOT_PROBE 11
#define BAD_SIGINFO 12
#define BAD_PPID 13
#define GOT_NOTHING 14

static sigset_t usr_set;

FN_SETUP(block_signals)
{
	sigemptyset(&usr_set);
	sigaddset(&usr_set, SIGUSR1);
	sigaddset(&usr_set, SIGUSR2);
	CHECK(sigprocmask(SIG_BLOCK, &usr_set, NULL));

	// Orphaned grandchildren are reparented to this process.
	CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1));
}
END_SETUP()

static void notify(int fd)
{
	char byte = 0;

	CHECK_WITH(write(fd, &byte, 1), _ret == 1);
	CHECK(close(fd));
}

static void wait_notified(int fd)
{
	char byte;

	CHECK_WITH(read(fd, &byte, 1), _ret == 1);
	CHECK(close(fd));
}

// Sets `SIGUSR1` as the parent-death signal, notifies `ready_fd`, and exits
// with a code describing the first signal received. `SIGUSR2` is a probe that
// shows the parent-death signal was not sent before it. If `same_ppid` is set,
// the parent process is expected to stay the same.
static void child_wait_pdeathsig(int ready_fd, pid_t parent, int same_ppid)
{
	siginfo_t info;

	CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1));
	notify(ready_fd);

	int sig = CHECK(sigwaitinfo(&usr_set, &info));
	if (sig == SIGUSR2) {
		struct timespec timeout = { .tv_sec = 0,
					    .tv_nsec = 100 * 1000 * 1000 };
		if (sigtimedwait(&usr_set, &info, &timeout) >= 0) {
			_exit(GOT_PDEATHSIG);
		}
		_exit(GOT_PROBE);
	}
	if (info.si_code != SI_USER || info.si_pid != parent) {
		_exit(BAD_SIGINFO);
	}
	if (same_ppid && getppid() != parent) {
		_exit(BAD_PPID);
	}
	_exit(GOT_PDEATHSIG);
}

static int wait_exit_code(pid_t pid)
{
	int status;

	CHECK_WITH(waitpid(pid, &status, 0), _ret == pid && WIFEXITED(status));
	return WEXITSTATUS(status);
}

FN_TEST(parent_process_exits)
{
	int pipe_fds[2];
	int ret_fds[2];

	TEST_SUCC(pipe(pipe_fds));
	TEST_SUCC(pipe(ret_fds));

	pid_t parent = TEST_SUCC(fork());
	if (parent == 0) {
		CHECK(close(ret_fds[0]));
		pid_t child = CHECK(fork());
		if (child == 0) {
			CHECK(close(pipe_fds[0]));
			CHECK(close(ret_fds[1]));
			child_wait_pdeathsig(pipe_fds[1], getppid(), 0);
		}
		CHECK_WITH(write(ret_fds[1], &child, sizeof(child)),
			   _ret == sizeof(child));
		CHECK(close(pipe_fds[1]));
		wait_notified(pipe_fds[0]);
		_exit(0);
	}
	TEST_SUCC(close(pipe_fds[0]));
	TEST_SUCC(close(pipe_fds[1]));
	TEST_SUCC(close(ret_fds[1]));

	pid_t child;
	TEST_RES(read(ret_fds[0], &child, sizeof(child)),
		 _ret == sizeof(child));
	TEST_SUCC(close(ret_fds[0]));

	TEST_RES(wait_exit_code(parent), _ret == 0);
	TEST_RES(wait_exit_code(child), _ret == GOT_PDEATHSIG);
}
END_TEST()

static int thread_pipe[2];
static pid_t thread_child;

static void *fork_and_exit(void *arg)
{
	(void)arg;

	thread_child = CHECK(fork());
	if (thread_child == 0) {
		CHECK(close(thread_pipe[0]));
		child_wait_pdeathsig(thread_pipe[1], getppid(), 1);
	}
	CHECK(close(thread_pipe[1]));
	wait_notified(thread_pipe[0]);
	return NULL;
}

static void *do_nothing(void *arg)
{
	return arg;
}

FN_TEST(parent_thread_exits)
{
	pid_t parent = TEST_SUCC(fork());
	if (parent == 0) {
		pthread_t thread;

		// The child of a thread receives the signal when the thread
		// exits, even though the parent process is still alive.
		CHECK(pipe(thread_pipe));
		CHECK(pthread_create(&thread, NULL, fork_and_exit, NULL));
		CHECK(pthread_join(thread, NULL));

		// The child is reparented to another thread in the same process.
		_exit(wait_exit_code(thread_child));
	}
	TEST_RES(wait_exit_code(parent), _ret == GOT_PDEATHSIG);
}
END_TEST()

FN_TEST(other_thread_exits)
{
	pid_t parent = TEST_SUCC(fork());
	if (parent == 0) {
		int pipe_fds[2];
		pthread_t thread;

		CHECK(pipe(pipe_fds));
		pid_t child = CHECK(fork());
		if (child == 0) {
			CHECK(close(pipe_fds[0]));
			child_wait_pdeathsig(pipe_fds[1], getppid(), 1);
		}
		CHECK(close(pipe_fds[1]));
		wait_notified(pipe_fds[0]);

		// The exit of a thread other than the parent thread does not
		// send the signal.
		CHECK(pthread_create(&thread, NULL, do_nothing, NULL));
		CHECK(pthread_join(thread, NULL));
		CHECK(kill(child, SIGUSR2));
		_exit(wait_exit_code(child));
	}
	TEST_RES(wait_exit_code(parent), _ret == GOT_PROBE);
}
END_TEST()

static int pdeathsig(void)
{
	int sig = -1;

	CHECK(prctl(PR_GET_PDEATHSIG, &sig));
	return sig;
}

static void *get_pdeathsig(void *arg)
{
	*(int *)arg = pdeathsig();
	return NULL;
}

static void *set_pdeathsig_and_notify(void *arg)
{
	CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1));
	notify(*(int *)arg);
	for (;;) {
		pause();
	}
	return NULL;
}

FN_TEST(per_thread_attribute)
{
	pthread_t thread;
	int sig;

	// A new thread or a new process does not inherit the signal.
	TEST_SUCC(prctl(PR_SET_PDEATHSIG, SIGUSR2));
	TEST_RES(pdeathsig(), _ret == SIGUSR2);
	TEST_SUCC(pthread_create(&thread, NULL, get_pdeathsig, &sig));
	TEST_SUCC(pthread_join(thread, NULL));
	TEST_RES(sig, _ret == 0);

	pid_t pid = TEST_SUCC(fork());
	if (pid == 0) {
		_exit(pdeathsig());
	}
	TEST_RES(wait_exit_code(pid), _ret == 0);
	TEST_SUCC(prctl(PR_SET_PDEATHSIG, 0));
	TEST_RES(pdeathsig(), _ret == 0);
}
END_TEST()

FN_TEST(set_by_other_thread)
{
	int pipe_fds[2];
	int ret_fds[2];

	TEST_SUCC(pipe(pipe_fds));
	TEST_SUCC(pipe(ret_fds));

	pid_t parent = TEST_SUCC(fork());
	if (parent == 0) {
		CHECK(close(ret_fds[0]));
		pid_t child = CHECK(fork());
		if (child == 0) {
			pthread_t thread;
			siginfo_t info;

			// The signal set by a non-main thread is sent to the
			// whole process.
			CHECK(close(pipe_fds[0]));
			CHECK(close(ret_fds[1]));
			CHECK(pthread_create(&thread, NULL,
					     set_pdeathsig_and_notify,
					     &pipe_fds[1]));
			int sig = CHECK(sigwaitinfo(&usr_set, &info));
			if (pdeathsig() != 0) {
				_exit(BAD_SIGINFO);
			}
			_exit(sig == SIGUSR1 ? GOT_PDEATHSIG : GOT_NOTHING);
		}
		CHECK_WITH(write(ret_fds[1], &child, sizeof(child)),
			   _ret == sizeof(child));
		CHECK(close(pipe_fds[1]));
		wait_notified(pipe_fds[0]);
		_exit(0);
	}
	TEST_SUCC(close(pipe_fds[0]));
	TEST_SUCC(close(pipe_fds[1]));
	TEST_SUCC(close(ret_fds[1]));

	pid_t child;
	TEST_RES(read(ret_fds[0], &child, sizeof(child)),
		 _ret == sizeof(child));
	TEST_SUCC(close(ret_fds[0]));

	TEST_RES(wait_exit_code(parent), _ret == 0);
	TEST_RES(wait_exit_code(child), _ret == GOT_PDEATHSIG);
}
END_TEST()
