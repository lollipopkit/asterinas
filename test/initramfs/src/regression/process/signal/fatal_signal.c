// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"

static char proc_state(pid_t pid)
{
	char path[64];
	char state = 0;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	FILE *file = fopen(path, "r");
	CHECK_WITH(0, file != NULL);
	CHECK_WITH(fscanf(file, "%*d %*s %c", &state), _ret == 1);
	CHECK(fclose(file));
	return state;
}

// Waits for the process `pid` to enter `state`.
static void wait_proc_state(pid_t pid, char state)
{
	struct timespec delay = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };

	for (int i = 0; i < 1000; i++) {
		if (proc_state(pid) == state) {
			return;
		}
		nanosleep(&delay, NULL);
	}
	CHECK_WITH(proc_state(pid), _ret == state);
}

// Returns whether the process `pid` is still alive after about 100 ms.
static int stays_alive(pid_t pid)
{
	struct timespec delay = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
	int status;

	for (int i = 0; i < 10; i++) {
		if (waitpid(pid, &status, WNOHANG) != 0) {
			return 0;
		}
		nanosleep(&delay, NULL);
	}
	return 1;
}

static void pause_forever(void)
{
	for (;;) {
		pause();
	}
}

static pid_t fork_stopped_sleeper(void)
{
	int status;
	pid_t pid = CHECK(fork());

	if (pid == 0) {
		pause_forever();
	}

	CHECK(kill(pid, SIGSTOP));
	CHECK_WITH(waitpid(pid, &status, WUNTRACED),
		   _ret == pid && WIFSTOPPED(status) &&
			   WSTOPSIG(status) == SIGSTOP);
	return pid;
}

FN_TEST(stopped_sigterm_until_sigcont)
{
	int status;
	pid_t pid = fork_stopped_sleeper();

	// A stopped process does not take a fatal signal other than `SIGKILL`
	// until it is continued.
	TEST_SUCC(kill(pid, SIGTERM));
	TEST_RES(stays_alive(pid), _ret == 1);
	TEST_RES(proc_state(pid), _ret == 'T');

	TEST_SUCC(kill(pid, SIGCONT));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFSIGNALED(status) &&
						   WTERMSIG(status) == SIGTERM);
}
END_TEST()

FN_TEST(stopped_sigkill)
{
	int status;
	pid_t pid = fork_stopped_sleeper();

	TEST_SUCC(kill(pid, SIGKILL));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFSIGNALED(status) &&
						   WTERMSIG(status) == SIGKILL);
}
END_TEST()

static int handler_pipe[2];

static void write_signum(int signum)
{
	char byte = signum;

	(void)!write(handler_pipe[1], &byte, 1);
}

FN_TEST(stopped_handler_until_sigcont)
{
	int status;
	char byte;
	struct pollfd pfd;

	TEST_SUCC(pipe(handler_pipe));

	pid_t pid = TEST_SUCC(fork());
	if (pid == 0) {
		CHECK(close(handler_pipe[0]));
		signal(SIGUSR1, write_signum);
		write_signum(0);
		pause_forever();
	}
	TEST_SUCC(close(handler_pipe[1]));
	TEST_RES(read(handler_pipe[0], &byte, 1), _ret == 1 && byte == 0);

	TEST_SUCC(kill(pid, SIGSTOP));
	TEST_RES(waitpid(pid, &status, WUNTRACED),
		 _ret == pid && WIFSTOPPED(status) &&
			 WSTOPSIG(status) == SIGSTOP);

	// The handler does not run while the process is stopped.
	TEST_SUCC(kill(pid, SIGUSR1));
	pfd.fd = handler_pipe[0];
	pfd.events = POLLIN;
	TEST_RES(poll(&pfd, 1, 100), _ret == 0);
	TEST_RES(proc_state(pid), _ret == 'T');

	// The handler runs once the process is continued.
	TEST_SUCC(kill(pid, SIGCONT));
	TEST_RES(read(handler_pipe[0], &byte, 1), _ret == 1 && byte == SIGUSR1);

	TEST_SUCC(kill(pid, SIGKILL));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFSIGNALED(status) &&
						   WTERMSIG(status) == SIGKILL);
	TEST_SUCC(close(handler_pipe[0]));
}
END_TEST()

static int blocker_pipe[2];
static volatile pid_t blocker_tid;

static void *block_in_read(void *arg)
{
	char byte;

	(void)arg;
	blocker_tid = syscall(SYS_gettid);
	(void)!read(blocker_pipe[0], &byte, 1);
	return NULL;
}

static pid_t fork_multithreaded(int block_sigterm_in_main, pid_t *tid)
{
	pid_t *shared_tid = CHECK_WITH(mmap(NULL, sizeof(pid_t),
					    PROT_READ | PROT_WRITE,
					    MAP_SHARED | MAP_ANONYMOUS, -1, 0),
				       _ret != MAP_FAILED);
	*shared_tid = 0;

	pid_t pid = CHECK(fork());
	if (pid == 0) {
		pthread_t thread;
		sigset_t set;

		CHECK(pipe(blocker_pipe));
		CHECK(pthread_create(&thread, NULL, block_in_read, NULL));
		while (blocker_tid == 0) {
			sched_yield();
		}
		if (block_sigterm_in_main) {
			sigemptyset(&set);
			sigaddset(&set, SIGTERM);
			CHECK(sigprocmask(SIG_BLOCK, &set, NULL));
		}
		*shared_tid = blocker_tid;
		pause_forever();
	}

	while (*(volatile pid_t *)shared_tid == 0) {
		sched_yield();
	}
	*tid = *shared_tid;
	CHECK(munmap(shared_tid, sizeof(pid_t)));

	wait_proc_state(pid, 'S');
	return pid;
}

FN_TEST(multithreaded_fatal_signal)
{
	int status;
	pid_t tid;
	pid_t pid;

	// The whole group exits with the fatal signal, even if the thread that
	// takes the signal is not the main thread.
	pid = fork_multithreaded(1, &tid);
	TEST_SUCC(kill(pid, SIGTERM));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFSIGNALED(status) &&
						   WTERMSIG(status) == SIGTERM);

	// A thread-directed fatal signal kills the whole group as well.
	pid = fork_multithreaded(0, &tid);
	TEST_SUCC(syscall(SYS_tgkill, pid, tid, SIGTERM));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFSIGNALED(status) &&
						   WTERMSIG(status) == SIGTERM);
}
END_TEST()

FN_TEST(sigtimedwait_not_fatal)
{
	int status;

	pid_t pid = TEST_SUCC(fork());
	if (pid == 0) {
		sigset_t set;
		siginfo_t info;

		sigemptyset(&set);
		sigaddset(&set, SIGTERM);
		CHECK(sigprocmask(SIG_BLOCK, &set, NULL));
		CHECK_WITH(sigwaitinfo(&set, &info), _ret == SIGTERM);
		_exit(0);
	}

	// The signal that is waited for in `sigtimedwait` is not fatal.
	wait_proc_state(pid, 'S');
	TEST_SUCC(kill(pid, SIGTERM));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()

FN_TEST(vfork_wait_killable)
{
	int status;

	pid_t *child_pid = CHECK_WITH(mmap(NULL, sizeof(pid_t),
					   PROT_READ | PROT_WRITE,
					   MAP_SHARED | MAP_ANONYMOUS, -1, 0),
				      _ret != MAP_FAILED);
	*child_pid = 0;

	// The vfork child is reparented to this process after its parent dies.
	TEST_SUCC(prctl(PR_SET_CHILD_SUBREAPER, 1));

	pid_t pid = TEST_SUCC(fork());
	if (pid == 0) {
		pid_t child = vfork();
		if (child == 0) {
			*child_pid = syscall(SYS_getpid);
			for (;;) {
				syscall(SYS_pause);
			}
		}
		_exit(1);
	}

	// A fatal signal kills the parent waiting for the vfork child.
	while (*(volatile pid_t *)child_pid == 0) {
		sched_yield();
	}
	wait_proc_state(pid, 'D');
	TEST_SUCC(kill(pid, SIGTERM));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFSIGNALED(status) &&
						   WTERMSIG(status) == SIGTERM);

	TEST_SUCC(kill(*child_pid, SIGKILL));
	TEST_RES(waitpid(*child_pid, &status, 0),
		 _ret == *child_pid && WIFSIGNALED(status) &&
			 WTERMSIG(status) == SIGKILL);

	TEST_SUCC(prctl(PR_SET_CHILD_SUBREAPER, 0));
	TEST_SUCC(munmap(child_pid, sizeof(pid_t)));
}
END_TEST()
