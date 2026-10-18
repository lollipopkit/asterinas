// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"
#include "../../common/yama_ptrace_scope.h"

static void pause_forever(void)
{
	for (;;) {
		pause();
	}
}

static pid_t fork_sleeper(void)
{
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		pause_forever();
	}
	return pid;
}

static void kill_and_reap(pid_t pid)
{
	int status;

	CHECK(kill(pid, SIGKILL));
	CHECK_WITH(waitpid(pid, &status, 0),
		   _ret == pid && WIFSIGNALED(status) &&
			   WTERMSIG(status) == SIGKILL);
}

#define IS_EVENT_STOP(status, sig)                                      \
	(WIFSTOPPED(status) && ((status) >> 16) == PTRACE_EVENT_STOP && \
	 WSTOPSIG(status) == (sig))

#define IS_SIGNAL_STOP(status, sig) \
	(WIFSTOPPED(status) && ((status) >> 8) == (sig))

FN_TEST(seize_interrupt)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(fork_sleeper());
	int status;
	siginfo_t si;
	unsigned long msg = 1;

	// `PTRACE_SEIZE` does not stop the tracee.
	TEST_SUCC(ptrace(PTRACE_SEIZE, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, WNOHANG), _ret == 0);
	// Requests that need a stopped tracee fail.
	TEST_ERRNO(ptrace(PTRACE_CONT, pid, 0, 0), ESRCH);
	TEST_ERRNO(ptrace(PTRACE_LISTEN, pid, 0, 0), ESRCH);
	TEST_ERRNO(ptrace(PTRACE_DETACH, pid, 0, 0), ESRCH);

	// `PTRACE_INTERRUPT` interrupts the blocking `pause` and traps the tracee.
	TEST_SUCC(ptrace(PTRACE_INTERRUPT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_EVENT_STOP(status, SIGTRAP));
	TEST_RES(ptrace(PTRACE_GETSIGINFO, pid, 0, &si),
		 si.si_signo == SIGTRAP &&
			 si.si_code == (SIGTRAP | PTRACE_EVENT_STOP << 8) &&
			 si.si_pid == pid && si.si_uid == getuid());
	TEST_RES(ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg), msg == 0);

	// A `PTRACE_INTERRUPT` during a trap takes effect after the trap ends.
	TEST_SUCC(ptrace(PTRACE_INTERRUPT, pid, 0, 0));
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_EVENT_STOP(status, SIGTRAP));

	// `PTRACE_LISTEN` outside a group-stop does not let the tracee run.
	TEST_SUCC(ptrace(PTRACE_LISTEN, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, WNOHANG), _ret == 0);
	TEST_ERRNO(ptrace(PTRACE_CONT, pid, 0, 0), ESRCH);
	TEST_SUCC(ptrace(PTRACE_INTERRUPT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_EVENT_STOP(status, SIGTRAP));

	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, WNOHANG), _ret == 0);

	TEST_SUCC(ptrace(PTRACE_INTERRUPT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_EVENT_STOP(status, SIGTRAP));
	TEST_SUCC(ptrace(PTRACE_DETACH, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, WNOHANG | WUNTRACED), _ret == 0);

	kill_and_reap(pid);
}
END_TEST()

FN_TEST(seize_group_stop_listen)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(fork_sleeper());
	int status;
	siginfo_t si;

	TEST_SUCC(ptrace(PTRACE_SEIZE, pid, 0, 0));

	// The stop signal is reported in a signal-delivery-stop first.
	TEST_SUCC(kill(pid, SIGSTOP));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_SIGNAL_STOP(status, SIGSTOP));
	TEST_RES(ptrace(PTRACE_GETSIGINFO, pid, 0, &si),
		 si.si_signo == SIGSTOP && si.si_code == SI_USER);
	TEST_ERRNO(ptrace(PTRACE_LISTEN, pid, 0, 0), EIO);

	// Delivering the stop signal starts a group-stop, which is reported as a
	// `PTRACE_EVENT_STOP` with the stop signal.
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, SIGSTOP));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_EVENT_STOP(status, SIGSTOP));
	TEST_RES(ptrace(PTRACE_GETSIGINFO, pid, 0, &si),
		 si.si_signo == SIGSTOP &&
			 si.si_code == (SIGSTOP | PTRACE_EVENT_STOP << 8));

	// The listening tracee is not reported by `wait` and cannot be operated.
	TEST_SUCC(ptrace(PTRACE_LISTEN, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, WNOHANG), _ret == 0);
	TEST_ERRNO(ptrace(PTRACE_CONT, pid, 0, 0), ESRCH);
	TEST_ERRNO(ptrace(PTRACE_GETSIGINFO, pid, 0, &si), ESRCH);
	TEST_ERRNO(ptrace(PTRACE_DETACH, pid, 0, 0), ESRCH);

	// `PTRACE_INTERRUPT` ends listening, and the group-stop is still in effect.
	TEST_SUCC(ptrace(PTRACE_INTERRUPT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_EVENT_STOP(status, SIGSTOP));

	// `SIGCONT` wakes up the listening tracee, which then reports the end of
	// the group-stop and the `SIGCONT` itself.
	TEST_SUCC(ptrace(PTRACE_LISTEN, pid, 0, 0));
	TEST_SUCC(kill(pid, SIGCONT));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_EVENT_STOP(status, SIGTRAP));
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_SIGNAL_STOP(status, SIGCONT));
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, WNOHANG), _ret == 0);

	kill_and_reap(pid);
}
END_TEST()

FN_TEST(seize_sigcont_running)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(fork_sleeper());
	int status;

	// A `SIGCONT` notifies a seized tracee even if it is not stopped.
	TEST_SUCC(ptrace(PTRACE_SEIZE, pid, 0, 0));
	TEST_SUCC(kill(pid, SIGCONT));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_EVENT_STOP(status, SIGTRAP));
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_SIGNAL_STOP(status, SIGCONT));
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, WNOHANG), _ret == 0);

	kill_and_reap(pid);
}
END_TEST()

FN_TEST(seize_stopped)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(fork_sleeper());
	int status;

	TEST_SUCC(kill(pid, SIGSTOP));
	TEST_RES(waitpid(pid, &status, WUNTRACED),
		 _ret == pid && WIFSTOPPED(status) &&
			 WSTOPSIG(status) == SIGSTOP);

	// Seizing a stopped tracee makes it re-trap into the group-stop.
	TEST_SUCC(ptrace(PTRACE_SEIZE, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, WNOHANG),
		 _ret == pid && IS_EVENT_STOP(status, SIGSTOP));

	// Detaching keeps the tracee stopped.
	TEST_SUCC(ptrace(PTRACE_DETACH, pid, 0, 0));
	TEST_SUCC(kill(pid, SIGCONT));
	TEST_RES(waitpid(pid, &status, WCONTINUED),
		 _ret == pid && WIFCONTINUED(status));

	kill_and_reap(pid);
}
END_TEST()

static void *exit_thread(void *arg)
{
	(void)arg;
	return NULL;
}

FN_TEST(seize_clone_auto_attach)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	int go_pipe[2];
	TEST_SUCC(pipe(go_pipe));

	pid_t pid = TEST_SUCC(fork());
	if (pid == 0) {
		char byte;
		pthread_t thread;

		CHECK_WITH(read(go_pipe[0], &byte, 1), _ret == 1);
		CHECK_WITH(pthread_create(&thread, NULL, exit_thread, NULL),
			   _ret == 0);
		CHECK_WITH(pthread_join(thread, NULL), _ret == 0);
		_exit(0);
	}

	int status;
	unsigned long msg;
	char byte = 0;

	// Options are given by `data` of `PTRACE_SEIZE`.
	TEST_SUCC(ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACECLONE));
	TEST_RES(write(go_pipe[1], &byte, 1), _ret == 1);

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFSTOPPED(status) &&
			 (status >> 8) == (SIGTRAP | PTRACE_EVENT_CLONE << 8));
	TEST_SUCC(ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg));
	pid_t tid = msg;

	// The new thread is seized and starts with a `PTRACE_EVENT_STOP`
	// instead of a `SIGSTOP`.
	TEST_RES(waitpid(tid, &status, __WALL),
		 _ret == tid && IS_EVENT_STOP(status, SIGTRAP));
	TEST_SUCC(ptrace(PTRACE_INTERRUPT, tid, 0, 0));
	TEST_SUCC(ptrace(PTRACE_CONT, tid, 0, 0));
	TEST_RES(waitpid(tid, &status, __WALL),
		 _ret == tid && IS_EVENT_STOP(status, SIGTRAP));
	TEST_SUCC(ptrace(PTRACE_CONT, tid, 0, 0));
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));

	TEST_RES(waitpid(tid, &status, __WALL),
		 _ret == tid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);

	TEST_SUCC(close(go_pipe[0]));
	TEST_SUCC(close(go_pipe[1]));
}
END_TEST()

// Forks a child that blocks in `read` on `fd` and exits with 0 if it reads one byte,
// or 1 if `read` fails (e.g., with `EINTR`).
static pid_t fork_reader(int fd)
{
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		char byte;
		_exit(read(fd, &byte, 1) == 1 ? 0 : 1);
	}

	// Wait for the child to sleep in `read`.
	struct timespec delay = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	for (int i = 0; i < 500; i++) {
		char state = 0;
		FILE *file = fopen(path, "r");
		CHECK_WITH(0, file != NULL);
		CHECK_WITH(fscanf(file, "%*d %*s %c", &state), _ret == 1);
		CHECK(fclose(file));
		if (state == 'S') {
			break;
		}
		nanosleep(&delay, NULL);
	}

	return pid;
}

FN_TEST(trap_restarts_syscall)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	int fds[2];
	int status;
	char byte = 0;
	TEST_SUCC(pipe(fds));

	// A blocking syscall interrupted by `PTRACE_INTERRUPT` is restarted.
	pid_t pid = TEST_SUCC(fork_reader(fds[0]));
	TEST_SUCC(ptrace(PTRACE_SEIZE, pid, 0, 0));
	TEST_SUCC(ptrace(PTRACE_INTERRUPT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_EVENT_STOP(status, SIGTRAP));
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, WNOHANG), _ret == 0);
	TEST_RES(write(fds[1], &byte, 1), _ret == 1);
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);

	// A blocking syscall interrupted by a suppressed signal is restarted.
	pid = TEST_SUCC(fork_reader(fds[0]));
	TEST_SUCC(ptrace(PTRACE_ATTACH, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_SIGNAL_STOP(status, SIGSTOP));
	TEST_SUCC(ptrace(PTRACE_DETACH, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, WNOHANG), _ret == 0);
	TEST_RES(write(fds[1], &byte, 1), _ret == 1);
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);

	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()
