// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"
#include "../../common/yama_ptrace_scope.h"

#define IS_EVENT_STOP(status, sig)                                      \
	(WIFSTOPPED(status) && ((status) >> 16) == PTRACE_EVENT_STOP && \
	 WSTOPSIG(status) == (sig))

#define IS_SIGNAL_STOP(status, sig) \
	(WIFSTOPPED(status) && ((status) >> 8) == (sig))

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

static char thread_state(pid_t pid, pid_t tid)
{
	char path[64];
	char state = 0;

	snprintf(path, sizeof(path), "/proc/%d/task/%d/stat", pid, tid);
	FILE *file = fopen(path, "r");
	CHECK_WITH(0, file != NULL);
	CHECK_WITH(fscanf(file, "%*d %*s %c", &state), _ret == 1);
	CHECK(fclose(file));
	return state;
}

// Waits for the thread `tid` of the process `pid` to enter `state`.
static void wait_thread_state(pid_t pid, pid_t tid, char state)
{
	struct timespec delay = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };

	for (int i = 0; i < 1000; i++) {
		if (thread_state(pid, tid) == state) {
			return;
		}
		nanosleep(&delay, NULL);
	}
	CHECK_WITH(thread_state(pid, tid), _ret == state);
}

FN_TEST(tracer_wait_continued)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(fork_sleeper());
	int status;

	TEST_SUCC(ptrace(PTRACE_ATTACH, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_SIGNAL_STOP(status, SIGSTOP));

	// Delivering `SIGSTOP` makes the tracee trap into the group stop.
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, SIGSTOP));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_SIGNAL_STOP(status, SIGSTOP));
	TEST_RES(waitpid(pid, &status, WNOHANG | WCONTINUED), _ret == 0);

	// `SIGCONT` does not resume the ptrace-stop, but the tracer can wait for
	// the continuation with `WCONTINUED`.
	TEST_SUCC(kill(pid, SIGCONT));
	TEST_RES(waitpid(pid, &status, WNOHANG), _ret == 0);
	TEST_RES(waitpid(pid, &status, WNOHANG | WCONTINUED),
		 _ret == pid && WIFCONTINUED(status));
	TEST_RES(waitpid(pid, &status, WNOHANG | WCONTINUED), _ret == 0);

	// The tracee is still in the ptrace-stop.
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_SIGNAL_STOP(status, SIGCONT));
	TEST_SUCC(ptrace(PTRACE_DETACH, pid, 0, 0));

	kill_and_reap(pid);
}
END_TEST()

struct waitid_resp {
	int ret;
	int err;
	pid_t pid;
	int code;
	int status;
};

static int real_parent_req_fd;
static int real_parent_resp_fd;

// Runs as the real parent of a sleeper, which executes `waitid` on the sleeper
// with the options received from `req_fd` and sends back the results.
static void run_real_parent(int req_fd, int resp_fd, int pid_fd)
{
	pid_t pid = fork_sleeper();
	CHECK_WITH(write(pid_fd, &pid, sizeof(pid)), _ret == sizeof(pid));

	for (;;) {
		int options;
		siginfo_t si;
		struct waitid_resp resp;

		CHECK_WITH(read(req_fd, &options, sizeof(options)),
			   _ret == sizeof(options));
		if (options == 0) {
			_exit(0);
		}

		memset(&si, 0, sizeof(si));
		errno = 0;
		resp.ret = waitid(P_PID, pid, &si, options);
		resp.err = errno;
		resp.pid = si.si_pid;
		resp.code = si.si_code;
		resp.status = si.si_status;
		CHECK_WITH(write(resp_fd, &resp, sizeof(resp)),
			   _ret == sizeof(resp));
	}
}

static struct waitid_resp real_parent_waitid(int options)
{
	struct waitid_resp resp;

	CHECK_WITH(write(real_parent_req_fd, &options, sizeof(options)),
		   _ret == sizeof(options));
	CHECK_WITH(read(real_parent_resp_fd, &resp, sizeof(resp)),
		   _ret == sizeof(resp));
	return resp;
}

#define IS_WAITID_NONE(resp) ((resp).ret == 0 && (resp).pid == 0)

#define IS_WAITID(resp, child, cld_code, si_status)                  \
	((resp).ret == 0 && (resp).pid == (child) &&                 \
	 (resp).code == (cld_code) && (resp).status == (si_status))

// Stops the running seized tracee `pid` with `SIGSTOP` until it traps into the
// group stop.
static void stop_seized(pid_t pid)
{
	int status;

	CHECK(kill(pid, SIGSTOP));
	CHECK_WITH(waitpid(pid, &status, 0),
		   _ret == pid && IS_SIGNAL_STOP(status, SIGSTOP));
	CHECK(ptrace(PTRACE_CONT, pid, 0, SIGSTOP));
	CHECK_WITH(waitpid(pid, &status, 0),
		   _ret == pid && IS_EVENT_STOP(status, SIGSTOP));
}

// Resumes the seized tracee `pid` in the group stop after `SIGCONT`.
static void resume_seized(pid_t pid)
{
	int status;

	CHECK(ptrace(PTRACE_CONT, pid, 0, 0));
	CHECK_WITH(waitpid(pid, &status, 0),
		   _ret == pid && IS_EVENT_STOP(status, SIGTRAP));
	CHECK(ptrace(PTRACE_CONT, pid, 0, 0));
	CHECK_WITH(waitpid(pid, &status, 0),
		   _ret == pid && IS_SIGNAL_STOP(status, SIGCONT));
	CHECK(ptrace(PTRACE_CONT, pid, 0, 0));
}

FN_TEST(real_parent_and_tracer)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	int req_pipe[2], resp_pipe[2], pid_pipe[2];
	int status;
	pid_t pid;

	TEST_SUCC(pipe(req_pipe));
	TEST_SUCC(pipe(resp_pipe));
	TEST_SUCC(pipe(pid_pipe));

	// The tracer (the current process) is the grandparent of the tracee.
	pid_t parent = TEST_SUCC(fork());
	if (parent == 0) {
		run_real_parent(req_pipe[0], resp_pipe[1], pid_pipe[1]);
	}
	real_parent_req_fd = req_pipe[1];
	real_parent_resp_fd = resp_pipe[0];
	TEST_RES(read(pid_pipe[0], &pid, sizeof(pid)), _ret == sizeof(pid));

	TEST_SUCC(ptrace(PTRACE_SEIZE, pid, 0, 0));

	// The real parent does not see the signal-delivery-stop.
	TEST_SUCC(kill(pid, SIGSTOP));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_SIGNAL_STOP(status, SIGSTOP));
	TEST_RES(real_parent_waitid(WSTOPPED | WNOHANG), IS_WAITID_NONE(_ret));

	// Both the real parent and the tracer see the group stop.
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, SIGSTOP));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && IS_EVENT_STOP(status, SIGSTOP));
	TEST_RES(waitpid(pid, &status, WNOHANG), _ret == 0);
	TEST_RES(real_parent_waitid(WSTOPPED | WNOWAIT),
		 IS_WAITID(_ret, pid, CLD_STOPPED, SIGSTOP));
	TEST_RES(real_parent_waitid(WSTOPPED),
		 IS_WAITID(_ret, pid, CLD_STOPPED, SIGSTOP));
	TEST_RES(real_parent_waitid(WSTOPPED | WNOHANG), IS_WAITID_NONE(_ret));

	// The continuation is reported once, here to the real parent.
	TEST_SUCC(kill(pid, SIGCONT));
	TEST_RES(real_parent_waitid(WCONTINUED),
		 IS_WAITID(_ret, pid, CLD_CONTINUED, SIGCONT));
	TEST_RES(waitpid(pid, &status, WNOHANG | WCONTINUED), _ret == 0);
	TEST_RES(real_parent_waitid(WCONTINUED | WNOHANG),
		 IS_WAITID_NONE(_ret));
	resume_seized(pid);

	// The continuation is reported once, here to the tracer.
	stop_seized(pid);
	TEST_RES(real_parent_waitid(WSTOPPED),
		 IS_WAITID(_ret, pid, CLD_STOPPED, SIGSTOP));
	TEST_SUCC(kill(pid, SIGCONT));
	TEST_RES(waitpid(pid, &status, WNOHANG | WCONTINUED),
		 _ret == pid && WIFCONTINUED(status));
	TEST_RES(waitpid(pid, &status, WNOHANG | WCONTINUED), _ret == 0);
	TEST_RES(real_parent_waitid(WCONTINUED | WNOHANG),
		 IS_WAITID_NONE(_ret));
	resume_seized(pid);

	// The exit is reported to the tracer first, then to the real parent.
	TEST_SUCC(kill(pid, SIGKILL));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFSIGNALED(status) &&
			 WTERMSIG(status) == SIGKILL);
	TEST_RES(real_parent_waitid(WEXITED),
		 IS_WAITID(_ret, pid, CLD_KILLED, SIGKILL));

	int quit = 0;
	TEST_RES(write(real_parent_req_fd, &quit, sizeof(quit)),
		 _ret == sizeof(quit));
	TEST_RES(waitpid(parent, &status, 0),
		 _ret == parent && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 0);

	TEST_SUCC(close(req_pipe[0]));
	TEST_SUCC(close(req_pipe[1]));
	TEST_SUCC(close(resp_pipe[0]));
	TEST_SUCC(close(resp_pipe[1]));
	TEST_SUCC(close(pid_pipe[0]));
	TEST_SUCC(close(pid_pipe[1]));
}
END_TEST()

static int tid_pipe[2];

static void *report_tid_and_pause(void *arg)
{
	(void)arg;

	pid_t tid = syscall(SYS_gettid);
	CHECK_WITH(write(tid_pipe[1], &tid, sizeof(tid)), _ret == sizeof(tid));
	pause_forever();
	return NULL;
}

FN_TEST(group_stop_completion)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	int status;
	siginfo_t si;
	pid_t tid;

	TEST_SUCC(pipe(tid_pipe));
	pid_t pid = TEST_SUCC(fork());
	if (pid == 0) {
		pthread_t thread;
		CHECK_WITH(pthread_create(&thread, NULL, report_tid_and_pause,
					  NULL),
			   _ret == 0);
		pause_forever();
	}
	TEST_RES(read(tid_pipe[0], &tid, sizeof(tid)), _ret == sizeof(tid));

	// Hold the non-main thread in a ptrace-stop.
	TEST_SUCC(ptrace(PTRACE_SEIZE, tid, 0, 0));
	TEST_SUCC(ptrace(PTRACE_INTERRUPT, tid, 0, 0));
	TEST_RES(waitpid(tid, &status, __WALL),
		 _ret == tid && IS_EVENT_STOP(status, SIGTRAP));

	// The group stop is not complete until the traced thread participates.
	TEST_SUCC(kill(pid, SIGSTOP));
	wait_thread_state(pid, pid, 'T');
	memset(&si, 0, sizeof(si));
	TEST_RES(waitid(P_PID, pid, &si, WSTOPPED | WNOHANG),
		 _ret == 0 && si.si_pid == 0);

	TEST_SUCC(ptrace(PTRACE_CONT, tid, 0, 0));
	TEST_RES(waitpid(tid, &status, __WALL),
		 _ret == tid && IS_EVENT_STOP(status, SIGSTOP));
	memset(&si, 0, sizeof(si));
	TEST_RES(waitid(P_PID, pid, &si, WSTOPPED),
		 _ret == 0 && si.si_pid == pid && si.si_code == CLD_STOPPED &&
			 si.si_status == SIGSTOP);

	TEST_SUCC(kill(pid, SIGKILL));
	TEST_RES(waitpid(tid, &status, __WALL),
		 _ret == tid && WIFSIGNALED(status) &&
			 WTERMSIG(status) == SIGKILL);
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFSIGNALED(status) &&
			 WTERMSIG(status) == SIGKILL);

	TEST_SUCC(close(tid_pipe[0]));
	TEST_SUCC(close(tid_pipe[1]));
}
END_TEST()
