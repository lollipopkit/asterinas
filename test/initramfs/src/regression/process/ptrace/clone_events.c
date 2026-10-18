// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"
#include "../../common/yama_ptrace_scope.h"

#define STACK_SIZE (1 << 20)
static char child_stack[STACK_SIZE];

static int child_exit_fn(void *arg)
{
	return 0;
}

static int ptrace_event_status(int event)
{
	return SIGTRAP | (event << 8);
}

// Forks a tracee that is stopped by `SIGSTOP` and then runs `tracee_fn`
// after the tracer sets `options` and continues it.
static pid_t start_tracee(void (*tracee_fn)(void), int options)
{
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		CHECK(ptrace(PTRACE_TRACEME, 0, 0, 0));
		CHECK(raise(SIGSTOP));
		tracee_fn();
		_exit(-1);
	}

	int status;
	CHECK_WITH(waitpid(pid, &status, 0), _ret == pid && WIFSTOPPED(status) &&
						     WSTOPSIG(status) == SIGSTOP);
	CHECK(ptrace(PTRACE_SETOPTIONS, pid, 0, options));
	CHECK(ptrace(PTRACE_CONT, pid, 0, 0));

	return pid;
}

static void wait_child_exited(pid_t child, int exit_code)
{
	int status;
	CHECK_WITH(waitpid(child, &status, 0),
		   _ret == child && WIFEXITED(status) &&
			   WEXITSTATUS(status) == exit_code);
}

static void tracee_clone_untraced(void)
{
	pid_t child = CHECK(clone(child_exit_fn, child_stack + STACK_SIZE,
				  CLONE_UNTRACED | SIGCHLD, NULL));
	wait_child_exited(child, 0);
	_exit(0);
}

FN_TEST(clone_untraced)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(start_tracee(
		tracee_clone_untraced, PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE |
					       PTRACE_O_TRACEVFORK));

	// No clone-family event is reported, and the child is not traced.
	int status;
	TEST_RES(waitpid(-1, &status, __WALL), _ret == pid &&
						       WIFSTOPPED(status) &&
						       (status >> 8) == SIGCHLD);
	TEST_RES(waitpid(-1, &status, __WALL | WNOHANG), _ret == 0);

	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFEXITED(status) &&
						   WEXITSTATUS(status) == 0);
}
END_TEST()

static void tracee_clone_ptrace(void)
{
	pid_t child = CHECK(clone(child_exit_fn, child_stack + STACK_SIZE,
				  CLONE_PTRACE | SIGCHLD, NULL));
	wait_child_exited(child, 0);
	_exit(0);
}

FN_TEST(clone_ptrace)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(start_tracee(tracee_clone_ptrace, 0));

	// The child is traced and stops with `SIGSTOP`, while no event is reported.
	int status;
	siginfo_t si;
	pid_t child = TEST_RES(waitpid(-1, &status, __WALL),
			       _ret != pid && WIFSTOPPED(status) &&
				       (status >> 8) == SIGSTOP);
	TEST_RES(ptrace(PTRACE_GETSIGINFO, child, 0, &si),
		 si.si_signo == SIGSTOP && si.si_code == SI_USER &&
			 si.si_pid == 0 && si.si_uid == 0);

	// The tracer waits for the child that is not its child with the default flags.
	TEST_SUCC(ptrace(PTRACE_CONT, child, 0, 0));
	TEST_RES(waitpid(child, &status, 0), _ret == child &&
						     WIFEXITED(status) &&
						     WEXITSTATUS(status) == 0);

	// The real parent is notified after the tracer reaps the child.
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFSTOPPED(status) &&
						   WSTOPSIG(status) == SIGCHLD);
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFEXITED(status) &&
						   WEXITSTATUS(status) == 0);
}
END_TEST()

static void tracee_vfork(void)
{
	if (CHECK(vfork()) == 0) {
		_exit(0);
	}
	_exit(0);
}

FN_TEST(vfork_done_only)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(start_tracee(tracee_vfork, PTRACE_O_TRACEVFORKDONE));

	// `PTRACE_O_TRACEVFORKDONE` alone does not trace the child.
	int status;
	unsigned long eventmsg;
	TEST_RES(waitpid(-1, &status, __WALL),
		 _ret == pid && WIFSTOPPED(status) &&
			 (status >> 8) ==
				 ptrace_event_status(PTRACE_EVENT_VFORK_DONE));
	TEST_RES(ptrace(PTRACE_GETEVENTMSG, pid, 0, &eventmsg),
		 eventmsg != 0 && eventmsg != pid);
	TEST_ERRNO(waitpid(eventmsg, &status, __WALL | WNOHANG), ECHILD);

	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFSTOPPED(status) &&
						   WSTOPSIG(status) == SIGCHLD);
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFEXITED(status) &&
						   WEXITSTATUS(status) == 0);
}
END_TEST()

static void tracee_fork_exec(void)
{
	pid_t child = CHECK(fork());
	if (child == 0) {
		char *const argv[] = { "/bin/true", NULL };
		char *const envp[] = { NULL };
		CHECK(execve("/bin/true", argv, envp));
		_exit(-1);
	}
	wait_child_exited(child, 0);
	_exit(0);
}

FN_TEST(fork_inherits_options)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(start_tracee(
		tracee_fork_exec, PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC));

	int status;
	unsigned long eventmsg;
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFSTOPPED(status) &&
			 (status >> 8) == ptrace_event_status(PTRACE_EVENT_FORK));
	TEST_SUCC(ptrace(PTRACE_GETEVENTMSG, pid, 0, &eventmsg));
	pid_t child = eventmsg;
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));

	TEST_RES(waitpid(child, &status, __WALL), _ret == child &&
							  WIFSTOPPED(status) &&
							  WSTOPSIG(status) ==
								  SIGSTOP);
	TEST_SUCC(ptrace(PTRACE_CONT, child, 0, 0));

	// The child inherits `PTRACE_O_TRACEEXEC`.
	TEST_RES(waitpid(child, &status, __WALL),
		 _ret == child && WIFSTOPPED(status) &&
			 (status >> 8) == ptrace_event_status(PTRACE_EVENT_EXEC));
	TEST_RES(ptrace(PTRACE_GETEVENTMSG, child, 0, &eventmsg),
		 eventmsg == child);
	TEST_SUCC(ptrace(PTRACE_CONT, child, 0, 0));
	TEST_RES(waitpid(child, &status, __WALL), _ret == child &&
							  WIFEXITED(status) &&
							  WEXITSTATUS(status) ==
								  0);

	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFSTOPPED(status) &&
						   WSTOPSIG(status) == SIGCHLD);
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFEXITED(status) &&
						   WEXITSTATUS(status) == 0);
}
END_TEST()

static void tracee_fork_wait(void)
{
	pid_t child = CHECK(fork());
	if (child == 0) {
		_exit(7);
	}
	wait_child_exited(child, 7);
	_exit(0);
}

FN_TEST(real_parent_waits_after_tracer_exits)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	int pid_pipe[2];
	TEST_SUCC(prctl(PR_SET_CHILD_SUBREAPER, 1));
	TEST_SUCC(pipe(pid_pipe));

	pid_t tracer_pid = TEST_SUCC(fork());
	if (tracer_pid == 0) {
		int status;
		unsigned long eventmsg;
		siginfo_t info;

		CHECK(close(pid_pipe[0]));
		pid_t pid = start_tracee(tracee_fork_wait, PTRACE_O_TRACEFORK);
		CHECK_WITH(waitpid(pid, &status, 0),
			   _ret == pid && WIFSTOPPED(status) &&
				   (status >> 8) ==
					   ptrace_event_status(PTRACE_EVENT_FORK));
		CHECK(ptrace(PTRACE_GETEVENTMSG, pid, 0, &eventmsg));
		pid_t child = eventmsg;

		CHECK_WITH(waitpid(child, &status, 0),
			   _ret == child && WIFSTOPPED(status) &&
				   WSTOPSIG(status) == SIGSTOP);
		CHECK(ptrace(PTRACE_CONT, child, 0, 0));
		// Let the child become a zombie without reaping it.
		CHECK_WITH(waitid(P_PID, child, &info, WEXITED | WNOWAIT),
			   info.si_pid == child && info.si_code == CLD_EXITED &&
				   info.si_status == 7);

		CHECK_WITH(write(pid_pipe[1], &pid, sizeof(pid)),
			   _ret == sizeof(pid));
		CHECK(close(pid_pipe[1]));
		// Exit while the tracee is stopped at the fork event.
		_exit(0);
	}

	TEST_SUCC(close(pid_pipe[1]));
	pid_t pid;
	TEST_RES(read(pid_pipe[0], &pid, sizeof(pid)), _ret == sizeof(pid));
	TEST_SUCC(close(pid_pipe[0]));

	// The real parent of the zombie child reaps it after the tracer exits.
	int status;
	TEST_RES(waitpid(tracer_pid, &status, 0),
		 _ret == tracer_pid && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 0);
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFEXITED(status) &&
						   WEXITSTATUS(status) == 0);

	TEST_SUCC(prctl(PR_SET_CHILD_SUBREAPER, 0));
}
END_TEST()
