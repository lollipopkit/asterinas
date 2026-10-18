// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"

#define EXEC_ID_CHILD_ENV "SIGCHLD_INFO_EXEC_ID_CHILD"
#define CHILD_UID 1234

static volatile sig_atomic_t received;
static siginfo_t received_info;

static void record_siginfo(int sig, siginfo_t *info, void *ucontext)
{
	(void)sig;
	(void)ucontext;

	received_info = *info;
	received = 1;
}

static void install_handler(int sig, int flags)
{
	struct sigaction action = {
		.sa_sigaction = record_siginfo,
		.sa_flags = SA_SIGINFO | flags,
	};

	CHECK(sigemptyset(&action.sa_mask));
	CHECK(sigaction(sig, &action, NULL));
}

static void reset_handler(int sig)
{
	CHECK_WITH(signal(sig, SIG_DFL), _ret != SIG_ERR);
}

// Waits for the handler to record a signal. `SIGCHLD` and `SIGUSR1` stay blocked outside of this
// function, so no signal can be missed.
static siginfo_t wait_siginfo(void)
{
	sigset_t mask;

	CHECK(sigemptyset(&mask));
	while (!received)
		sigsuspend(&mask);
	received = 0;

	return received_info;
}

static int is_pending(int sig)
{
	sigset_t pending;

	CHECK(sigpending(&pending));
	return sigismember(&pending, sig);
}

static void burn_cpu_time(void)
{
	clock_t start = clock();

	while (clock() - start < CLOCKS_PER_SEC / 5)
		;
}

// The real parent is notified with `SIGCHLD` instead of a custom exit signal if it has executed a
// new program after creating the child. This runs in the parent after it executes a new program.
FN_SETUP(exec_id_child)
{
	const char *env = getenv(EXEC_ID_CHILD_ENV);
	sigset_t mask;
	siginfo_t info;
	pid_t cpid;

	if (env == NULL)
		return;
	cpid = atoi(env);

	CHECK(sigemptyset(&mask));
	CHECK(sigaddset(&mask, SIGCHLD));
	CHECK(sigaddset(&mask, SIGUSR1));
	CHECK_WITH(sigwaitinfo(&mask, &info), _ret == SIGCHLD);
	CHECK_WITH(info.si_code, _ret == CLD_EXITED);
	CHECK_WITH(info.si_pid, _ret == cpid);
	CHECK_WITH(info.si_status, _ret == 7);
	CHECK_WITH(waitpid(cpid, NULL, __WALL), _ret == cpid);

	exit(EXIT_SUCCESS);
}
END_SETUP()

FN_SETUP(block_signals)
{
	sigset_t mask;

	CHECK(sigemptyset(&mask));
	CHECK(sigaddset(&mask, SIGCHLD));
	CHECK(sigaddset(&mask, SIGUSR1));
	CHECK(sigprocmask(SIG_BLOCK, &mask, NULL));
}
END_SETUP()

FN_TEST(exited)
{
	uid_t uid = geteuid() == 0 ? CHILD_UID : getuid();
	siginfo_t info;
	pid_t cpid;

	install_handler(SIGCHLD, 0);

	cpid = TEST_SUCC(fork());
	if (cpid == 0) {
		if (geteuid() == 0)
			CHECK(setresuid(CHILD_UID, CHILD_UID, CHILD_UID));
		burn_cpu_time();
		_exit(3);
	}

	info = wait_siginfo();
	TEST_RES(info.si_signo, _ret == SIGCHLD);
	TEST_RES(info.si_code, _ret == CLD_EXITED);
	TEST_RES(info.si_pid, _ret == cpid);
	TEST_RES(info.si_uid, _ret == uid);
	TEST_RES(info.si_status, _ret == 3);
	// The child has spent at least 0.2 seconds of CPU time, which is 20 clock ticks.
	TEST_RES(info.si_utime + info.si_stime, _ret >= 10);

	memset(&info, 0, sizeof(info));
	TEST_RES(waitid(P_PID, cpid, &info, WEXITED),
		 info.si_signo == SIGCHLD && info.si_code == CLD_EXITED &&
			 info.si_pid == cpid && info.si_uid == uid &&
			 info.si_status == 3);

	reset_handler(SIGCHLD);
}
END_TEST()

FN_TEST(killed)
{
	siginfo_t info;
	pid_t cpid;

	install_handler(SIGCHLD, 0);

	cpid = TEST_SUCC(fork());
	if (cpid == 0) {
		for (;;)
			pause();
	}

	TEST_SUCC(kill(cpid, SIGKILL));

	info = wait_siginfo();
	TEST_RES(info.si_code, _ret == CLD_KILLED);
	TEST_RES(info.si_pid, _ret == cpid);
	TEST_RES(info.si_uid, _ret == getuid());
	TEST_RES(info.si_status, _ret == SIGKILL);

	memset(&info, 0, sizeof(info));
	TEST_RES(waitid(P_PID, cpid, &info, WEXITED),
		 info.si_code == CLD_KILLED && info.si_pid == cpid &&
			 info.si_status == SIGKILL);

	reset_handler(SIGCHLD);
}
END_TEST()

FN_TEST(stopped_and_continued)
{
	siginfo_t info;
	pid_t cpid;

	install_handler(SIGCHLD, 0);

	cpid = TEST_SUCC(fork());
	if (cpid == 0) {
		sigset_t mask;

		// A blocked `SIGCONT` still continues the process.
		CHECK(sigemptyset(&mask));
		CHECK(sigaddset(&mask, SIGCONT));
		CHECK(sigprocmask(SIG_BLOCK, &mask, NULL));
		for (;;)
			pause();
	}

	TEST_SUCC(kill(cpid, SIGSTOP));
	info = wait_siginfo();
	TEST_RES(info.si_code, _ret == CLD_STOPPED);
	TEST_RES(info.si_pid, _ret == cpid);
	TEST_RES(info.si_uid, _ret == getuid());
	TEST_RES(info.si_status, _ret == SIGSTOP);

	memset(&info, 0, sizeof(info));
	TEST_RES(waitid(P_PID, cpid, &info, WSTOPPED),
		 info.si_code == CLD_STOPPED && info.si_pid == cpid &&
			 info.si_status == SIGSTOP);

	TEST_SUCC(kill(cpid, SIGCONT));
	info = wait_siginfo();
	TEST_RES(info.si_code, _ret == CLD_CONTINUED);
	TEST_RES(info.si_pid, _ret == cpid);
	TEST_RES(info.si_status, _ret == SIGCONT);

	memset(&info, 0, sizeof(info));
	TEST_RES(waitid(P_PID, cpid, &info, WCONTINUED),
		 info.si_code == CLD_CONTINUED && info.si_pid == cpid &&
			 info.si_status == SIGCONT);

	TEST_SUCC(kill(cpid, SIGKILL));
	info = wait_siginfo();
	TEST_RES(info.si_code, _ret == CLD_KILLED);
	TEST_RES(waitpid(cpid, NULL, 0), _ret == cpid);

	reset_handler(SIGCHLD);
}
END_TEST()

FN_TEST(no_cld_stop)
{
	siginfo_t info;
	pid_t cpid;
	int status;

	install_handler(SIGCHLD, SA_NOCLDSTOP);

	cpid = TEST_SUCC(fork());
	if (cpid == 0) {
		for (;;)
			pause();
	}

	TEST_SUCC(kill(cpid, SIGSTOP));
	TEST_RES(waitpid(cpid, &status, WUNTRACED),
		 _ret == cpid && WIFSTOPPED(status) &&
			 WSTOPSIG(status) == SIGSTOP);
	TEST_RES(is_pending(SIGCHLD), _ret == 0);

	TEST_SUCC(kill(cpid, SIGCONT));
	TEST_RES(waitpid(cpid, &status, WCONTINUED),
		 _ret == cpid && WIFCONTINUED(status));
	TEST_RES(is_pending(SIGCHLD), _ret == 0);

	// `SA_NOCLDSTOP` does not affect the notification of the child's death.
	TEST_SUCC(kill(cpid, SIGKILL));
	info = wait_siginfo();
	TEST_RES(info.si_code, _ret == CLD_KILLED);
	TEST_RES(info.si_pid, _ret == cpid);
	TEST_RES(waitpid(cpid, NULL, 0), _ret == cpid);

	reset_handler(SIGCHLD);
}
END_TEST()

FN_TEST(traced)
{
	siginfo_t info;
	pid_t cpid;
	int status;

	install_handler(SIGCHLD, 0);

	cpid = TEST_SUCC(fork());
	if (cpid == 0) {
		CHECK(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
		CHECK(raise(SIGSTOP));
		_exit(5);
	}

	info = wait_siginfo();
	TEST_RES(info.si_code, _ret == CLD_TRAPPED);
	TEST_RES(info.si_pid, _ret == cpid);
	TEST_RES(info.si_uid, _ret == getuid());
	TEST_RES(info.si_status, _ret == SIGSTOP);
	TEST_RES(waitpid(cpid, &status, 0),
		 _ret == cpid && WIFSTOPPED(status) &&
			 WSTOPSIG(status) == SIGSTOP);

	TEST_SUCC(ptrace(PTRACE_CONT, cpid, NULL, NULL));
	info = wait_siginfo();
	TEST_RES(info.si_code, _ret == CLD_EXITED);
	TEST_RES(info.si_pid, _ret == cpid);
	TEST_RES(info.si_status, _ret == 5);
	TEST_RES(waitpid(cpid, &status, 0),
		 _ret == cpid && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 5);

	reset_handler(SIGCHLD);
}
END_TEST()

FN_TEST(custom_exit_signal)
{
	siginfo_t info;
	pid_t cpid;

	install_handler(SIGUSR1, 0);

	// With a zero stack and no other flags, `clone` behaves like `fork`.
	cpid = TEST_SUCC(syscall(SYS_clone, SIGUSR1, 0, 0, 0, 0));
	if (cpid == 0)
		_exit(4);

	info = wait_siginfo();
	TEST_RES(info.si_signo, _ret == SIGUSR1);
	TEST_RES(info.si_code, _ret == CLD_EXITED);
	TEST_RES(info.si_pid, _ret == cpid);
	TEST_RES(info.si_status, _ret == 4);
	TEST_RES(is_pending(SIGCHLD), _ret == 0);
	TEST_RES(waitpid(cpid, NULL, __WALL), _ret == cpid);

	reset_handler(SIGUSR1);
}
END_TEST()

FN_TEST(custom_exit_signal_after_exec)
{
	pid_t ppid;
	int status;

	ppid = TEST_SUCC(fork());
	if (ppid == 0) {
		char env[16];
		pid_t cpid;

		cpid = CHECK(syscall(SYS_clone, SIGUSR1, 0, 0, 0, 0));
		if (cpid == 0) {
			usleep(200 * 1000);
			_exit(7);
		}

		snprintf(env, sizeof(env), "%d", cpid);
		CHECK(setenv(EXEC_ID_CHILD_ENV, env, 1));
		CHECK(execl("/proc/self/exe", "sigchld_info", NULL));
	}

	TEST_RES(waitpid(ppid, &status, 0),
		 _ret == ppid && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);
}
END_TEST()

FN_TEST(ignored_autoreap)
{
	pid_t cpid;

	CHECK_WITH(signal(SIGCHLD, SIG_IGN), _ret != SIG_ERR);

	cpid = TEST_SUCC(fork());
	if (cpid == 0)
		_exit(0);

	// The child is reaped automatically, so `wait` fails after the child exits.
	TEST_ERRNO(wait(NULL), ECHILD);
	TEST_ERRNO(kill(cpid, 0), ESRCH);

	reset_handler(SIGCHLD);
	TEST_RES(is_pending(SIGCHLD), _ret == 0);
}
END_TEST()

FN_TEST(no_cld_wait_autoreap)
{
	siginfo_t info;
	pid_t cpid;

	install_handler(SIGCHLD, SA_NOCLDWAIT);

	cpid = TEST_SUCC(fork());
	if (cpid == 0)
		_exit(6);

	TEST_ERRNO(wait(NULL), ECHILD);
	TEST_ERRNO(kill(cpid, 0), ESRCH);

	// `SA_NOCLDWAIT` does not suppress `SIGCHLD`.
	info = wait_siginfo();
	TEST_RES(info.si_code, _ret == CLD_EXITED);
	TEST_RES(info.si_pid, _ret == cpid);
	TEST_RES(info.si_status, _ret == 6);

	reset_handler(SIGCHLD);
}
END_TEST()
