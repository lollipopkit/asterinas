// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../common/test.h"
#include "../common/yama_ptrace_scope.h"

// Forks a child that exits with `code` after reading one byte from `fd`.
static pid_t fork_waiting_child(int fd, int code)
{
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		char byte;
		CHECK_WITH(read(fd, &byte, 1), _ret == 1);
		_exit(code);
	}
	return pid;
}

FN_TEST(wclone_and_wall)
{
	int go_pipe[2];
	int status;
	siginfo_t si;
	char bytes[2] = { 0 };

	TEST_SUCC(pipe(go_pipe));

	// A child that sends no signal to its parent on exit is a "clone" child.
	pid_t clone_child = TEST_SUCC(syscall(SYS_clone, 0, 0, 0, 0, 0));
	if (clone_child == 0) {
		char byte;
		CHECK_WITH(read(go_pipe[0], &byte, 1), _ret == 1);
		_exit(5);
	}
	pid_t fork_child = TEST_SUCC(fork_waiting_child(go_pipe[0], 6));

	TEST_ERRNO(waitpid(clone_child, &status, WNOHANG), ECHILD);
	TEST_RES(waitpid(clone_child, &status, WNOHANG | __WCLONE), _ret == 0);
	TEST_RES(waitpid(clone_child, &status, WNOHANG | __WALL), _ret == 0);
	TEST_ERRNO(waitpid(fork_child, &status, WNOHANG | __WCLONE), ECHILD);
	TEST_RES(waitpid(fork_child, &status, WNOHANG | __WCLONE | __WALL),
		 _ret == 0);

	TEST_RES(write(go_pipe[1], bytes, 2), _ret == 2);

	memset(&si, 0, sizeof(si));
	TEST_RES(waitid(P_PID, clone_child, &si, WEXITED | WNOWAIT | __WALL),
		 _ret == 0 && si.si_pid == clone_child &&
			 si.si_code == CLD_EXITED && si.si_status == 5);
	TEST_ERRNO(waitid(P_PID, clone_child, &si, WEXITED | WNOHANG), ECHILD);
	TEST_RES(waitpid(-1, &status, __WCLONE),
		 _ret == clone_child && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 5);
	TEST_RES(waitpid(-1, &status, 0),
		 _ret == fork_child && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 6);
	TEST_ERRNO(waitpid(-1, &status, __WALL), ECHILD);

	TEST_SUCC(close(go_pipe[0]));
	TEST_SUCC(close(go_pipe[1]));
}
END_TEST()

FN_TEST(waitid_info_and_rusage)
{
	int go_pipe[2];
	siginfo_t si;
	struct rusage ru;
	char byte = 0;

	TEST_SUCC(pipe(go_pipe));
	pid_t child = TEST_SUCC(fork_waiting_child(go_pipe[0], 9));

	// If no child is waited for, the `siginfo_t` fields are zeroed.
	memset(&si, 0xff, sizeof(si));
	TEST_RES(waitid(P_PID, child, &si, WEXITED | WNOHANG),
		 _ret == 0 && si.si_signo == 0 && si.si_errno == 0 &&
			 si.si_code == 0 && si.si_pid == 0 && si.si_uid == 0 &&
			 si.si_status == 0);

	TEST_RES(write(go_pipe[1], &byte, 1), _ret == 1);

	// The resource usage of the child is reported.
	memset(&si, 0xff, sizeof(si));
	memset(&ru, 0xff, sizeof(ru));
	TEST_RES(syscall(SYS_waitid, P_PID, child, &si, WEXITED, &ru),
		 _ret == 0 && si.si_signo == SIGCHLD && si.si_errno == 0 &&
			 si.si_code == CLD_EXITED && si.si_pid == child &&
			 si.si_uid == getuid() && si.si_status == 9 &&
			 ru.ru_utime.tv_sec >= 0 && ru.ru_utime.tv_usec >= 0 &&
			 ru.ru_utime.tv_usec < 1000000 &&
			 ru.ru_stime.tv_sec >= 0 && ru.ru_stime.tv_usec >= 0 &&
			 ru.ru_stime.tv_usec < 1000000);

	TEST_SUCC(close(go_pipe[0]));
	TEST_SUCC(close(go_pipe[1]));
}
END_TEST()

// A helper thread that runs the commands sent by the main thread.
struct helper {
	pthread_t thread;
	pid_t tid;
	int cmd_pipe[2];
	int done_pipe[2];
	// For `CMD_FORK`.
	int child_fd;
	pid_t child;
	// For `CMD_WAITID`.
	int options;
	int ret;
	int err;
	siginfo_t si;
};

enum {
	CMD_FORK = 1,
	CMD_WAITID,
	CMD_QUIT,
};

static void *run_helper(void *arg)
{
	struct helper *helper = arg;

	helper->tid = syscall(SYS_gettid);

	for (;;) {
		char cmd;
		CHECK_WITH(read(helper->cmd_pipe[0], &cmd, 1), _ret == 1);

		switch (cmd) {
		case CMD_FORK:
			helper->child = fork_waiting_child(helper->child_fd, 7);
			break;
		case CMD_WAITID:
			memset(&helper->si, 0, sizeof(helper->si));
			errno = 0;
			helper->ret = waitid(P_PID, helper->child, &helper->si,
					     helper->options);
			helper->err = errno;
			break;
		case CMD_QUIT:
			return NULL;
		}

		CHECK_WITH(write(helper->done_pipe[1], &cmd, 1), _ret == 1);
	}
}

static void helper_start(struct helper *helper)
{
	CHECK(pipe(helper->cmd_pipe));
	CHECK(pipe(helper->done_pipe));
	CHECK_WITH(pthread_create(&helper->thread, NULL, run_helper, helper),
		   _ret == 0);
}

static void helper_run(struct helper *helper, char cmd)
{
	CHECK_WITH(write(helper->cmd_pipe[1], &cmd, 1), _ret == 1);
	CHECK_WITH(read(helper->done_pipe[0], &cmd, 1), _ret == 1);
}

static int helper_waitid(struct helper *helper, int options)
{
	helper->options = options;
	helper_run(helper, CMD_WAITID);
	errno = helper->err;
	return helper->ret;
}

static void helper_stop(struct helper *helper)
{
	char cmd = CMD_QUIT;
	char path[64];
	struct timespec delay = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };

	CHECK_WITH(write(helper->cmd_pipe[1], &cmd, 1), _ret == 1);
	CHECK_WITH(pthread_join(helper->thread, NULL), _ret == 0);

	// `pthread_join` may return before the thread is fully released, so
	// wait for the thread to disappear.
	snprintf(path, sizeof(path), "/proc/self/task/%d", helper->tid);
	for (int i = 0; i < 1000 && access(path, F_OK) == 0; i++) {
		nanosleep(&delay, NULL);
	}
	CHECK_WITH(access(path, F_OK), _ret < 0 && errno == ENOENT);
	CHECK(close(helper->cmd_pipe[0]));
	CHECK(close(helper->cmd_pipe[1]));
	CHECK(close(helper->done_pipe[0]));
	CHECK(close(helper->done_pipe[1]));
}

FN_TEST(wnothread)
{
	struct helper helper;
	int go_pipe[2];
	int status;
	char byte = 0;

	TEST_SUCC(pipe(go_pipe));
	helper_start(&helper);
	helper.child_fd = go_pipe[0];
	helper_run(&helper, CMD_FORK);
	pid_t child = helper.child;

	// With `__WNOTHREAD`, only the children of the calling thread are waited for.
	TEST_RES(helper_waitid(&helper, WEXITED | WNOHANG | __WNOTHREAD),
		 _ret == 0 && helper.si.si_pid == 0);
	TEST_ERRNO(waitpid(child, &status, WNOHANG | __WNOTHREAD), ECHILD);
	TEST_ERRNO(waitpid(-1, &status, WNOHANG | __WNOTHREAD), ECHILD);
	TEST_RES(waitpid(child, &status, WNOHANG), _ret == 0);

	// The children of an exited thread are inherited by another thread.
	helper_stop(&helper);
	TEST_RES(waitpid(child, &status, WNOHANG | __WNOTHREAD), _ret == 0);

	TEST_RES(write(go_pipe[1], &byte, 1), _ret == 1);
	TEST_RES(waitpid(child, &status, __WNOTHREAD),
		 _ret == child && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 7);

	TEST_SUCC(close(go_pipe[0]));
	TEST_SUCC(close(go_pipe[1]));
}
END_TEST()

#define IS_EVENT_STOP_INFO(si, child, sig)                         \
	((si).si_pid == (child) && (si).si_code == CLD_TRAPPED && \
	 (si).si_status == ((sig) | PTRACE_EVENT_STOP << 8))

FN_TEST(wnothread_ptrace)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	struct helper helper;
	int go_pipe[2];
	int status;
	siginfo_t si;
	char byte = 0;

	TEST_SUCC(pipe(go_pipe));
	helper_start(&helper);
	helper.child_fd = go_pipe[0];
	helper_run(&helper, CMD_FORK);
	pid_t child = helper.child;

	// The main thread traces the child of the helper thread.
	TEST_SUCC(ptrace(PTRACE_SEIZE, child, 0, 0));
	TEST_SUCC(ptrace(PTRACE_INTERRUPT, child, 0, 0));
	memset(&si, 0, sizeof(si));
	TEST_RES(waitid(P_PID, child, &si, WSTOPPED | WNOWAIT),
		 _ret == 0 && IS_EVENT_STOP_INFO(si, child, SIGTRAP));

	// Both the tracer thread and the real parent thread see the ptrace-stop
	// with `__WNOTHREAD`, since the tracer is in the real parent process.
	memset(&si, 0, sizeof(si));
	TEST_RES(waitid(P_PID, child, &si,
			WSTOPPED | WNOHANG | WNOWAIT | __WNOTHREAD),
		 _ret == 0 && IS_EVENT_STOP_INFO(si, child, SIGTRAP));
	TEST_RES(helper_waitid(&helper,
			       WSTOPPED | WNOHANG | WNOWAIT | __WNOTHREAD),
		 _ret == 0 && IS_EVENT_STOP_INFO(helper.si, child, SIGTRAP));
	TEST_RES(helper_waitid(&helper, WSTOPPED | WNOHANG | __WNOTHREAD),
		 _ret == 0 && IS_EVENT_STOP_INFO(helper.si, child, SIGTRAP));
	TEST_RES(waitid(P_PID, child, &si, WSTOPPED | WNOHANG | __WNOTHREAD),
		 _ret == 0 && si.si_pid == 0);

	TEST_SUCC(ptrace(PTRACE_DETACH, child, 0, 0));
	TEST_ERRNO(waitpid(child, &status, WNOHANG | __WNOTHREAD), ECHILD);

	TEST_RES(write(go_pipe[1], &byte, 1), _ret == 1);
	TEST_RES(helper_waitid(&helper, WEXITED | __WNOTHREAD),
		 _ret == 0 && helper.si.si_pid == child &&
			 helper.si.si_code == CLD_EXITED &&
			 helper.si.si_status == 7);
	helper_stop(&helper);

	TEST_SUCC(close(go_pipe[0]));
	TEST_SUCC(close(go_pipe[1]));
}
END_TEST()
