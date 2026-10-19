// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"
#include "../../common/yama_ptrace_scope.h"

static void exit_with_42_handler(int sig)
{
	(void)sig;
	_exit(42);
}

static void install_handler(int sig, void (*handler)(int))
{
	struct sigaction action = {
		.sa_handler = handler,
		.sa_flags = 0,
	};

	CHECK(sigemptyset(&action.sa_mask));
	CHECK(sigaction(sig, &action, NULL));
}

static void pause_forever(void)
{
	for (;;) {
		pause();
	}
}

// Forks a child that sleeps forever. `SIGUSR1` makes it exit with 42.
static pid_t fork_sleeper(void)
{
	int ready_pipe[2];
	char byte = 0;

	CHECK(pipe(ready_pipe));
	pid_t pid = CHECK(fork());
	if (pid == 0) {
		install_handler(SIGUSR1, exit_with_42_handler);
		CHECK_WITH(write(ready_pipe[1], &byte, 1), _ret == 1);
		pause_forever();
	}
	CHECK_WITH(read(ready_pipe[0], &byte, 1), _ret == 1);
	CHECK(close(ready_pipe[0]));
	CHECK(close(ready_pipe[1]));
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

static int read_status_field(pid_t pid, const char *field)
{
	char path[64];
	char line[256];
	size_t len = strlen(field);
	int value = -1;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	FILE *file = fopen(path, "r");
	CHECK_WITH(0, file != NULL);
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strncmp(line, field, len) == 0 && line[len] == ':') {
			value = atoi(line + len + 1);
			break;
		}
	}
	CHECK(fclose(file));
	return value;
}

static char read_state(pid_t pid)
{
	char path[64];
	char line[256];
	char state = '?';

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	FILE *file = fopen(path, "r");
	CHECK_WITH(0, file != NULL);
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strncmp(line, "State:\t", 7) == 0) {
			state = line[7];
			break;
		}
	}
	CHECK(fclose(file));
	return state;
}

// Waits until the state of `pid` in procfs becomes `state` for at most 5 seconds.
static int wait_for_state(pid_t pid, char state)
{
	struct timespec delay = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };

	for (int i = 0; i < 500; i++) {
		if (read_state(pid) == state) {
			return 0;
		}
		nanosleep(&delay, NULL);
	}
	errno = ETIMEDOUT;
	return -1;
}

FN_TEST(attach_wait_detach)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(fork_sleeper());
	int status;
	siginfo_t si;

	TEST_SUCC(ptrace(PTRACE_ATTACH, pid, 0, 0));
	TEST_RES(read_status_field(pid, "TracerPid"), _ret == getpid());

	// `PTRACE_ATTACH` sends a `SIGSTOP` as a kernel-generated signal.
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFSTOPPED(status) && (status >> 8) == SIGSTOP);
	TEST_RES(ptrace(PTRACE_GETSIGINFO, pid, 0, &si),
		 si.si_signo == SIGSTOP && si.si_code == SI_KERNEL &&
			 si.si_pid == 0 && si.si_uid == 0);
	TEST_RES(read_state(pid), _ret == 't');

	// A tracee can only be attached once.
	TEST_ERRNO(ptrace(PTRACE_ATTACH, pid, 0, 0), EPERM);
	TEST_ERRNO(ptrace(PTRACE_SEIZE, pid, 0, 0), EPERM);
	// `PTRACE_INTERRUPT` and `PTRACE_LISTEN` require `PTRACE_SEIZE`.
	TEST_ERRNO(ptrace(PTRACE_INTERRUPT, pid, 0, 0), EIO);
	TEST_ERRNO(ptrace(PTRACE_LISTEN, pid, 0, 0), EIO);
	TEST_ERRNO(ptrace(PTRACE_DETACH, pid, 0, 1000), EIO);

	// Detaching suppresses the `SIGSTOP` and resumes the tracee.
	TEST_SUCC(ptrace(PTRACE_DETACH, pid, 0, 0));
	TEST_RES(read_status_field(pid, "TracerPid"), _ret == 0);
	TEST_ERRNO(ptrace(PTRACE_CONT, pid, 0, 0), ESRCH);
	TEST_ERRNO(ptrace(PTRACE_DETACH, pid, 0, 0), ESRCH);
	TEST_SUCC(wait_for_state(pid, 'S'));
	TEST_RES(waitpid(pid, &status, WNOHANG | WUNTRACED), _ret == 0);

	// The tracee can be attached again after detaching.
	TEST_SUCC(ptrace(PTRACE_ATTACH, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFSTOPPED(status) &&
						   WSTOPSIG(status) == SIGSTOP);
	TEST_SUCC(ptrace(PTRACE_DETACH, pid, 0, 0));

	kill_and_reap(pid);
}
END_TEST()

FN_TEST(detach_with_signal)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(fork_sleeper());
	int status;

	TEST_SUCC(ptrace(PTRACE_ATTACH, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFSTOPPED(status) &&
						   WSTOPSIG(status) == SIGSTOP);

	// The signal given to `PTRACE_DETACH` is delivered to the tracee.
	TEST_SUCC(ptrace(PTRACE_DETACH, pid, 0, SIGUSR1));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 42);
}
END_TEST()

FN_TEST(attach_stopped)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(fork_sleeper());
	int status;
	siginfo_t si;

	TEST_SUCC(kill(pid, SIGSTOP));
	TEST_RES(waitpid(pid, &status, WUNTRACED),
		 _ret == pid && WIFSTOPPED(status) &&
			 WSTOPSIG(status) == SIGSTOP);

	// Attaching to a stopped tracee makes it re-trap into the group-stop,
	// which is observable without waiting.
	TEST_SUCC(ptrace(PTRACE_ATTACH, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, WNOHANG),
		 _ret == pid && WIFSTOPPED(status) && (status >> 8) == SIGSTOP);
	TEST_RES(read_state(pid), _ret == 't');
	// A group-stop has no `siginfo` if the tracee is not seized.
	TEST_ERRNO(ptrace(PTRACE_GETSIGINFO, pid, 0, &si), EINVAL);

	// The tracee leaves the group-stop and reports the `SIGSTOP` sent by
	// `PTRACE_ATTACH`.
	TEST_SUCC(ptrace(PTRACE_CONT, pid, 0, 0));
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFSTOPPED(status) && (status >> 8) == SIGSTOP);
	TEST_RES(ptrace(PTRACE_GETSIGINFO, pid, 0, &si),
		 si.si_signo == SIGSTOP && si.si_code == SI_KERNEL);

	// Detaching keeps the tracee in the group-stop that is still in effect.
	TEST_SUCC(ptrace(PTRACE_DETACH, pid, 0, 0));
	TEST_SUCC(wait_for_state(pid, 'T'));
	TEST_RES(waitpid(pid, &status, WNOHANG | WUNTRACED), _ret == 0);

	TEST_SUCC(kill(pid, SIGCONT));
	TEST_RES(waitpid(pid, &status, WCONTINUED),
		 _ret == pid && WIFCONTINUED(status));
	TEST_SUCC(wait_for_state(pid, 'S'));

	kill_and_reap(pid);
}
END_TEST()

FN_TEST(attach_errors)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	// A process cannot trace itself.
	TEST_ERRNO(ptrace(PTRACE_ATTACH, getpid(), 0, 0), EPERM);
	TEST_ERRNO(ptrace(PTRACE_SEIZE, getpid(), 0, 0), EPERM);

	// A nonexistent thread cannot be traced.
	TEST_ERRNO(ptrace(PTRACE_ATTACH, 0x3fffffff, 0, 0), ESRCH);

	// Kernel threads cannot be traced.
	char comm[32] = { 0 };
	int fd = open("/proc/2/comm", O_RDONLY);
	if (fd >= 0) {
		CHECK(read(fd, comm, sizeof(comm) - 1));
		CHECK(close(fd));
	}
	if (strcmp(comm, "kthreadd\n") == 0) {
		TEST_ERRNO(ptrace(PTRACE_ATTACH, 2, 0, 0), EPERM);
	}

	pid_t pid = TEST_SUCC(fork_sleeper());

	// Invalid arguments of `PTRACE_SEIZE`.
	TEST_ERRNO(ptrace(PTRACE_SEIZE, pid, 1, 0), EIO);
	TEST_ERRNO(ptrace(PTRACE_SEIZE, pid, 0, 1ul << 30), EIO);
	// Without seccomp support (Asterinas) or `CAP_SYS_ADMIN` (Linux
	// regular users), `PTRACE_O_SUSPEND_SECCOMP` is rejected.
	errno = 0;
	int ret = ptrace(PTRACE_SEIZE, pid, 0, 1ul << 21);
	int err = errno;
	TEST_RES(ret, _ret == -1 && (err == EINVAL || err == EPERM));
	TEST_RES(read_status_field(pid, "TracerPid"), _ret == 0);

	// Requests other than attaching require the tracee to be traced.
	TEST_ERRNO(ptrace(PTRACE_DETACH, pid, 0, 0), ESRCH);
	TEST_ERRNO(ptrace(PTRACE_INTERRUPT, pid, 0, 0), ESRCH);

	kill_and_reap(pid);
}
END_TEST()

struct thread_args {
	int tid_pipe;
};

static void *sleeper_thread(void *arg)
{
	struct thread_args *args = arg;
	pid_t tid = syscall(SYS_gettid);

	CHECK_WITH(write(args->tid_pipe, &tid, sizeof(tid)),
		   _ret == sizeof(tid));
	pause_forever();
	return NULL;
}

FN_TEST(attach_non_main_thread)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	int tid_pipe[2];
	TEST_SUCC(pipe(tid_pipe));

	pid_t pid = TEST_SUCC(fork());
	if (pid == 0) {
		struct thread_args args = { .tid_pipe = tid_pipe[1] };
		pthread_t thread;
		CHECK_WITH(pthread_create(&thread, NULL, sleeper_thread, &args),
			   _ret == 0);
		pause_forever();
	}

	pid_t tid;
	TEST_RES(read(tid_pipe[0], &tid, sizeof(tid)),
		 _ret == sizeof(tid) && tid != pid);
	TEST_SUCC(close(tid_pipe[0]));
	TEST_SUCC(close(tid_pipe[1]));

	int status;
	TEST_SUCC(ptrace(PTRACE_ATTACH, tid, 0, 0));
	TEST_RES(read_status_field(tid, "TracerPid"), _ret == getpid());
	TEST_RES(read_status_field(pid, "TracerPid"), _ret == 0);

	// Only the attached thread stops for the tracer.
	TEST_RES(waitpid(tid, &status, 0), _ret == tid && WIFSTOPPED(status) &&
						   WSTOPSIG(status) == SIGSTOP);
	TEST_ERRNO(ptrace(PTRACE_CONT, pid, 0, 0), ESRCH);
	// The main thread may not have reached `pause()` yet.
	TEST_SUCC(wait_for_state(pid, 'S'));

	TEST_SUCC(ptrace(PTRACE_DETACH, tid, 0, 0));
	TEST_RES(read_status_field(tid, "TracerPid"), _ret == 0);

	kill_and_reap(pid);
}
END_TEST()

struct tracer_args {
	pid_t tracee;
	int to_main[2];
	int to_tracer[2];
	int ret;
};

static void *attach_and_exit_thread(void *arg)
{
	struct tracer_args *args = arg;

	args->ret = ptrace(PTRACE_ATTACH, args->tracee, 0, 0);
	return NULL;
}

static void *attach_and_stay_thread(void *arg)
{
	struct tracer_args *args = arg;
	char byte = 0;

	CHECK(ptrace(PTRACE_ATTACH, args->tracee, 0, 0));
	CHECK_WITH(write(args->to_main[1], &byte, 1), _ret == 1);
	CHECK_WITH(read(args->to_tracer[0], &byte, 1), _ret == 1);
	args->ret = ptrace(PTRACE_DETACH, args->tracee, 0, SIGUSR1);
	return NULL;
}

FN_TEST(tracer_non_main_thread)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	pid_t pid = TEST_SUCC(fork_sleeper());
	struct tracer_args args = { .tracee = pid };
	pthread_t thread;
	int status;
	char byte = 0;

	// A non-main thread attaches to the tracee and exits afterwards, which
	// detaches the tracee. The pending `SIGSTOP` then stops the tracee.
	TEST_RES(pthread_create(&thread, NULL, attach_and_exit_thread, &args),
		 _ret == 0);
	TEST_RES(pthread_join(thread, NULL), _ret == 0);
	TEST_RES(args.ret, _ret == 0);
	TEST_SUCC(wait_for_state(pid, 'T'));
	TEST_RES(read_status_field(pid, "TracerPid"), _ret == 0);
	TEST_RES(waitpid(pid, &status, WUNTRACED),
		 _ret == pid && WIFSTOPPED(status) &&
			 WSTOPSIG(status) == SIGSTOP);
	TEST_SUCC(kill(pid, SIGCONT));
	TEST_SUCC(wait_for_state(pid, 'S'));

	// A non-main thread attaches to the tracee and stays alive.
	TEST_SUCC(pipe(args.to_main));
	TEST_SUCC(pipe(args.to_tracer));
	TEST_RES(pthread_create(&thread, NULL, attach_and_stay_thread, &args),
		 _ret == 0);
	TEST_RES(read(args.to_main[0], &byte, 1), _ret == 1);
	TEST_RES(read_status_field(pid, "TracerPid"),
		 _ret > 0 && _ret != getpid());

	// Other threads in the tracer process can wait for the tracee,
	// but only the tracer thread can operate on it.
	TEST_RES(waitpid(pid, &status, 0), _ret == pid && WIFSTOPPED(status) &&
						   WSTOPSIG(status) == SIGSTOP);
	TEST_ERRNO(ptrace(PTRACE_CONT, pid, 0, 0), ESRCH);
	TEST_ERRNO(ptrace(PTRACE_ATTACH, pid, 0, 0), EPERM);

	TEST_RES(write(args.to_tracer[1], &byte, 1), _ret == 1);
	TEST_RES(pthread_join(thread, NULL), _ret == 0);
	TEST_RES(args.ret, _ret == 0);
	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 42);

	TEST_SUCC(close(args.to_main[0]));
	TEST_SUCC(close(args.to_main[1]));
	TEST_SUCC(close(args.to_tracer[0]));
	TEST_SUCC(close(args.to_tracer[1]));
}
END_TEST()

// Forks a tracer that attaches to its child and exits without detaching.
// Returns the PID of the tracee, which is reparented to this process.
static pid_t fork_exiting_tracer(int seize_options)
{
	int pid_pipe[2];
	int status;

	CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1));
	CHECK(pipe(pid_pipe));

	pid_t tracer = CHECK(fork());
	if (tracer == 0) {
		CHECK(close(pid_pipe[0]));
		pid_t tracee = fork_sleeper();
		if (seize_options < 0) {
			CHECK(ptrace(PTRACE_ATTACH, tracee, 0, 0));
			CHECK_WITH(waitpid(tracee, &status, 0),
				   _ret == tracee && WIFSTOPPED(status) &&
					   WSTOPSIG(status) == SIGSTOP);
		} else {
			CHECK(ptrace(PTRACE_SEIZE, tracee, 0, seize_options));
			CHECK(ptrace(PTRACE_INTERRUPT, tracee, 0, 0));
			CHECK_WITH(waitpid(tracee, &status, 0),
				   _ret == tracee && WIFSTOPPED(status) &&
					   (status >> 16) == PTRACE_EVENT_STOP);
		}
		CHECK_WITH(write(pid_pipe[1], &tracee, sizeof(tracee)),
			   _ret == sizeof(tracee));
		_exit(0);
	}

	CHECK(close(pid_pipe[1]));
	pid_t tracee;
	CHECK_WITH(read(pid_pipe[0], &tracee, sizeof(tracee)),
		   _ret == sizeof(tracee));
	CHECK(close(pid_pipe[0]));
	CHECK_WITH(waitpid(tracer, &status, 0),
		   _ret == tracer && WIFEXITED(status) &&
			   WEXITSTATUS(status) == 0);
	CHECK(prctl(PR_SET_CHILD_SUBREAPER, 0));

	return tracee;
}

FN_TEST(tracer_exit_detaches)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	int status;

	// The tracee resumes after its tracer exits.
	pid_t tracee = TEST_SUCC(fork_exiting_tracer(-1));
	TEST_SUCC(wait_for_state(tracee, 'S'));
	TEST_RES(read_status_field(tracee, "TracerPid"), _ret == 0);
	TEST_SUCC(kill(tracee, SIGUSR1));
	TEST_RES(waitpid(tracee, &status, 0),
		 _ret == tracee && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 42);

	tracee = TEST_SUCC(fork_exiting_tracer(0));
	TEST_SUCC(wait_for_state(tracee, 'S'));
	TEST_SUCC(kill(tracee, SIGUSR1));
	TEST_RES(waitpid(tracee, &status, 0),
		 _ret == tracee && WIFEXITED(status) &&
			 WEXITSTATUS(status) == 42);

	// With `PTRACE_O_EXITKILL`, the tracee is killed after its tracer exits.
	tracee = TEST_SUCC(fork_exiting_tracer(PTRACE_O_EXITKILL));
	TEST_RES(waitpid(tracee, &status, 0),
		 _ret == tracee && WIFSIGNALED(status) &&
			 WTERMSIG(status) == SIGKILL);
}
END_TEST()
