// SPDX-License-Identifier: MPL-2.0

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../../common/test.h"

// A fault signal is forced. If it is blocked or ignored, the kernel must still
// terminate the faulting process. Otherwise, the process returns to the
// faulting instruction and faults again forever.

static void fault(void)
{
	*(volatile int *)NULL = 0;
}

static void fault_with_sigsegv_blocked(void)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGSEGV);
	sigprocmask(SIG_BLOCK, &set, NULL);
	fault();
}

static void fault_with_sigsegv_ignored(void)
{
	signal(SIGSEGV, SIG_IGN);
	fault();
}

static void fault_with_sigsegv_blocked_and_ignored(void)
{
	signal(SIGSEGV, SIG_IGN);
	fault_with_sigsegv_blocked();
}

#define TEST_CHILD_KILLED_BY_SIGSEGV(func)             \
	pid = TEST_SUCC(fork());                       \
	if (pid == 0) {                                \
		func();                                \
		exit(EXIT_FAILURE);                    \
	}                                              \
                                                       \
	TEST_RES(waitpid(pid, &status, 0),             \
		 _ret == pid && WIFSIGNALED(status) && \
			 WTERMSIG(status) == SIGSEGV);

FN_TEST(blocked_fault_signal)
{
	pid_t pid;
	int status;

	TEST_CHILD_KILLED_BY_SIGSEGV(fault_with_sigsegv_blocked);
}
END_TEST()

FN_TEST(ignored_fault_signal)
{
	pid_t pid;
	int status;

	TEST_CHILD_KILLED_BY_SIGSEGV(fault_with_sigsegv_ignored);
}
END_TEST()

FN_TEST(blocked_and_ignored_fault_signal)
{
	pid_t pid;
	int status;

	TEST_CHILD_KILLED_BY_SIGSEGV(fault_with_sigsegv_blocked_and_ignored);
}
END_TEST()
