// SPDX-License-Identifier: MPL-2.0

// Tests how interrupted syscalls are restarted or fail with `EINTR`.
//
// Each syscall runs in a child process and is interrupted in one of the following ways:
//  - A stop signal followed by `SIGCONT`, or a `PTRACE_INTERRUPT` trap. No user signal handler
//    runs, so the syscall restarts transparently (except for those that never restart).
//  - A signal whose handler does not have `SA_RESTART`. The syscall fails with `EINTR`.
//  - A signal whose handler has `SA_RESTART`. Only the `ERESTARTSYS` class restarts.
//  - A stop signal, and a signal with a handler that is sent during the stop. The syscall is
//    interrupted by the handler after the stop.

#define _GNU_SOURCE

#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <linux/futex.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "../../common/test.h"
#include "../../common/yama_ptrace_scope.h"

#define TIMEOUT_MS 500
#define INTERRUPT_AT_MS 100
#define STOP_FOR_MS 200
// The tolerance of the elapsed time. Note that a syscall that should honor the total timeout but
// restarts with the remaining timeout takes `STOP_FOR_MS` more.
#define SLACK_MS 150

static long now_ms(void)
{
	struct timespec ts;

	CHECK(clock_gettime(CLOCK_MONOTONIC, &ts));
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sleep_ms(long ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (ms % 1000) * 1000000 };

	CHECK(nanosleep(&ts, NULL));
}

static long timespec_ms(const struct timespec *ts)
{
	return ts->tv_sec * 1000 + ts->tv_nsec / 1000000;
}

// Syscalls under test

struct result {
	long ret;
	int err;
	long elapsed_ms;
	// The remaining time written back by the syscall in milliseconds, or -1.
	long remain_ms;
	int handled;
};

static volatile sig_atomic_t handled;

static void handler(int sig)
{
	(void)sig;
	handled = 1;
}

static uint32_t *shared_futex;
static int data_pipe[2];

static long op_nanosleep(struct result *r)
{
	struct timespec req = { .tv_sec = 0, .tv_nsec = TIMEOUT_MS * 1000000L };
	struct timespec rem = { .tv_sec = -1, .tv_nsec = -1 };

	long ret = nanosleep(&req, &rem);
	if (rem.tv_sec != -1)
		r->remain_ms = timespec_ms(&rem);
	return ret;
}

static long do_clock_nanosleep(clockid_t clockid, int flags,
			       const struct timespec *req, struct timespec *rem)
{
	int err = clock_nanosleep(clockid, flags, req, rem);
	if (err != 0) {
		errno = err;
		return -1;
	}
	return 0;
}

static long op_clock_nanosleep_abs(struct result *r)
{
	struct timespec req;

	(void)r;
	CHECK(clock_gettime(CLOCK_MONOTONIC, &req));
	req.tv_nsec += TIMEOUT_MS * 1000000L;
	if (req.tv_nsec >= 1000000000L) {
		req.tv_sec += 1;
		req.tv_nsec -= 1000000000L;
	}
	return do_clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &req, NULL);
}

static long op_clock_nanosleep_realtime(struct result *r)
{
	struct timespec req = { .tv_sec = 0, .tv_nsec = TIMEOUT_MS * 1000000L };
	struct timespec rem = { .tv_sec = -1, .tv_nsec = -1 };

	long ret = do_clock_nanosleep(CLOCK_REALTIME, 0, &req, &rem);
	if (rem.tv_sec != -1)
		r->remain_ms = timespec_ms(&rem);
	return ret;
}

static long op_poll(struct result *r)
{
	(void)r;
	return poll(NULL, 0, TIMEOUT_MS);
}

static long op_ppoll(struct result *r)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = TIMEOUT_MS * 1000000L };

	// Use the raw syscall to see the remaining time written back.
	long ret = syscall(SYS_ppoll, NULL, 0, &ts, NULL, 0);
	r->remain_ms = timespec_ms(&ts);
	return ret;
}

static long op_select(struct result *r)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = TIMEOUT_MS * 1000L };

	(void)r;
	return select(0, NULL, NULL, NULL, &tv);
}

static long op_pselect6(struct result *r)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = TIMEOUT_MS * 1000000L };

	// Use the raw syscall to see the remaining time written back.
	long ret = syscall(SYS_pselect6, 0, NULL, NULL, NULL, &ts, NULL);
	r->remain_ms = timespec_ms(&ts);
	return ret;
}

static long op_epoll_wait(struct result *r)
{
	struct epoll_event event;
	int epfd = CHECK(epoll_create1(0));

	(void)r;
	return epoll_wait(epfd, &event, 1, TIMEOUT_MS);
}

static long op_futex_timed(struct result *r)
{
	uint32_t word = 0;
	struct timespec ts = { .tv_sec = 0, .tv_nsec = TIMEOUT_MS * 1000000L };

	(void)r;
	return syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, &ts, NULL, 0);
}

static long op_futex_bitset_abs(struct result *r)
{
	uint32_t word = 0;
	struct timespec ts;

	(void)r;
	CHECK(clock_gettime(CLOCK_MONOTONIC, &ts));
	ts.tv_nsec += TIMEOUT_MS * 1000000L;
	if (ts.tv_nsec >= 1000000000L) {
		ts.tv_sec += 1;
		ts.tv_nsec -= 1000000000L;
	}
	return syscall(SYS_futex, &word, FUTEX_WAIT_BITSET_PRIVATE, 0, &ts,
		       NULL, FUTEX_BITSET_MATCH_ANY);
}

static long op_pause(struct result *r)
{
	(void)r;
	return pause();
}

static long op_sigsuspend(struct result *r)
{
	sigset_t mask;

	(void)r;
	sigemptyset(&mask);
	return sigsuspend(&mask);
}

static long op_futex(struct result *r)
{
	(void)r;
	return syscall(SYS_futex, shared_futex, FUTEX_WAIT, 0, NULL, NULL, 0);
}

static long op_read(struct result *r)
{
	char buf;

	(void)r;
	return read(data_pipe[0], &buf, 1);
}

// The ways to finish a syscall that waits forever
enum finish {
	// The syscall finishes by itself.
	FINISH_NONE,
	// The syscall is finished by `SIGUSR1`, whose handler does not have `SA_RESTART`.
	FINISH_SIGNAL,
	FINISH_FUTEX_WAKE,
	FINISH_PIPE_WRITE,
};

// The ways to interrupt the syscall
enum interrupt {
	BY_STOP,
	BY_PTRACE,
	BY_HANDLER,
	BY_RESTART_HANDLER,
	BY_STOP_AND_HANDLER,
};

static void kill_and_wait_stopped(pid_t pid)
{
	int status;

	CHECK(kill(pid, SIGSTOP));
	CHECK_WITH(waitpid(pid, &status, WUNTRACED),
		   _ret == pid && WIFSTOPPED(status) &&
			   WSTOPSIG(status) == SIGSTOP);
}

static void ptrace_interrupt_and_wait(pid_t pid)
{
	int status;

	CHECK(ptrace(PTRACE_INTERRUPT, pid, 0, 0));
	CHECK_WITH(waitpid(pid, &status, 0),
		   _ret == pid && WIFSTOPPED(status) &&
			   (status >> 16) == PTRACE_EVENT_STOP);
}

static int result_ready(int fd)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	return CHECK(poll(&pfd, 1, 0));
}

static struct result do_run(const char *name, long (*op)(struct result *),
			    enum interrupt how, enum finish finish)
{
	int sync_pipe[2], result_pipe[2];
	struct result r = { .remain_ms = -1 };
	char byte = 0;
	int status;

	CHECK(pipe(sync_pipe));
	CHECK(pipe(result_pipe));
	CHECK(pipe(data_pipe));
	*shared_futex = 0;

	pid_t pid = CHECK(fork());
	if (pid == 0) {
		struct sigaction sa = { .sa_handler = handler };

		if (how == BY_RESTART_HANDLER)
			sa.sa_flags = SA_RESTART;
		CHECK(sigaction(SIGUSR1, &sa, NULL));

		CHECK(write(sync_pipe[1], &byte, 1));
		long start = now_ms();
		r.ret = op(&r);
		r.err = errno;
		r.elapsed_ms = now_ms() - start;
		r.handled = handled;
		CHECK(write(result_pipe[1], &r, sizeof(r)));
		_exit(EXIT_SUCCESS);
	}

	if (how == BY_PTRACE)
		CHECK(ptrace(PTRACE_SEIZE, pid, 0, 0));

	CHECK(read(sync_pipe[0], &byte, 1));
	sleep_ms(INTERRUPT_AT_MS);

	switch (how) {
	case BY_STOP:
		kill_and_wait_stopped(pid);
		sleep_ms(STOP_FOR_MS);
		CHECK(kill(pid, SIGCONT));
		break;
	case BY_PTRACE:
		ptrace_interrupt_and_wait(pid);
		sleep_ms(STOP_FOR_MS);
		CHECK(ptrace(PTRACE_CONT, pid, 0, 0));
		break;
	case BY_HANDLER:
	case BY_RESTART_HANDLER:
		CHECK(kill(pid, SIGUSR1));
		break;
	case BY_STOP_AND_HANDLER:
		kill_and_wait_stopped(pid);
		CHECK(kill(pid, SIGUSR1));
		sleep_ms(STOP_FOR_MS);
		CHECK(kill(pid, SIGCONT));
		break;
	}

	if (finish != FINISH_NONE) {
		// The syscall should still be waiting.
		sleep_ms(STOP_FOR_MS);
		if (result_ready(result_pipe[0])) {
			finish = FINISH_NONE;
		} else if (how == BY_PTRACE) {
			// Detach so that the finishing signal is not reported to us.
			ptrace_interrupt_and_wait(pid);
			CHECK(ptrace(PTRACE_DETACH, pid, 0, 0));
		}
	}

	switch (finish) {
	case FINISH_NONE:
		break;
	case FINISH_SIGNAL:
		CHECK(kill(pid, SIGUSR1));
		break;
	case FINISH_FUTEX_WAKE:
		while (!result_ready(result_pipe[0]) &&
		       CHECK(syscall(SYS_futex, shared_futex, FUTEX_WAKE, 1,
				     NULL, NULL, 0)) == 0)
			sleep_ms(10);
		break;
	case FINISH_PIPE_WRITE:
		CHECK(write(data_pipe[1], &byte, 1));
		break;
	}

	CHECK_WITH(read(result_pipe[0], &r, sizeof(r)), _ret == sizeof(r));
	CHECK_WITH(waitpid(pid, &status, 0),
		   _ret == pid && WIFEXITED(status) &&
			   WEXITSTATUS(status) == EXIT_SUCCESS);

	CHECK(close(sync_pipe[0]));
	CHECK(close(sync_pipe[1]));
	CHECK(close(result_pipe[0]));
	CHECK(close(result_pipe[1]));
	CHECK(close(data_pipe[0]));
	CHECK(close(data_pipe[1]));

	fprintf(stderr,
		"%s (interrupt %d): ret = %ld, errno = %d, elapsed = %ld ms, remain = %ld ms, handled = %d\n",
		name, how, r.ret, r.err, r.elapsed_ms, r.remain_ms, r.handled);
	return r;
}

FN_SETUP(shared_futex)
{
	shared_futex = CHECK_WITH(mmap(NULL, sizeof(*shared_futex),
				       PROT_READ | PROT_WRITE,
				       MAP_SHARED | MAP_ANONYMOUS, -1, 0),
				  _ret != MAP_FAILED);
}
END_SETUP()

FN_TEST(restart_syscall_without_restart_block)
{
	TEST_ERRNO(syscall(SYS_restart_syscall), EINTR);
}
END_TEST()

// Checks of the results

static int is_elapsed(const struct result *r, long ms)
{
	return r->elapsed_ms >= ms - 1 && r->elapsed_ms < ms + SLACK_MS;
}

static int is_timed_out(const struct result *r, long ret, int err)
{
	return r->ret == ret && r->err == err && is_elapsed(r, TIMEOUT_MS);
}

// The remaining time is written back on interruption.
static int has_remain(const struct result *r)
{
	return r->remain_ms > 0 && r->remain_ms < TIMEOUT_MS;
}

static int is_eintr(const struct result *r)
{
	return r->ret == -1 && r->err == EINTR;
}

static int is_late(const struct result *r)
{
	return r->elapsed_ms >= INTERRUPT_AT_MS + STOP_FOR_MS;
}

static int timed_out(const struct result *r)
{
	return is_timed_out(r, 0, 0);
}

static int timed_out_with_remain(const struct result *r)
{
	return is_timed_out(r, 0, 0) && has_remain(r);
}

// The remaining time is written back when the syscall is interrupted, and the restarted syscall
// uses the remaining time. So the time during the stop is not counted.
static int timed_out_after_stop(const struct result *r)
{
	return r->ret == 0 && r->err == 0 &&
	       is_elapsed(r, TIMEOUT_MS + STOP_FOR_MS);
}

static int timed_out_after_stop_with_zero_remain(const struct result *r)
{
	return timed_out_after_stop(r) && r->remain_ms == 0;
}

static int futex_timed_out(const struct result *r)
{
	return is_timed_out(r, -1, ETIMEDOUT);
}

static int eintr_handled(const struct result *r)
{
	return is_eintr(r) && r->handled;
}

static int eintr_handled_with_remain(const struct result *r)
{
	return is_eintr(r) && r->handled && has_remain(r);
}

static int eintr_handled_late(const struct result *r)
{
	return is_eintr(r) && r->handled && is_late(r);
}

static int eintr_unhandled(const struct result *r)
{
	return is_eintr(r) && !r->handled;
}

static int woken_late(const struct result *r)
{
	return r->ret == 0 && !r->handled && is_late(r);
}

static int woken_handled(const struct result *r)
{
	return r->ret == 0 && r->handled;
}

static int read_late(const struct result *r)
{
	return r->ret == 1 && !r->handled && is_late(r);
}

static int read_handled(const struct result *r)
{
	return r->ret == 1 && r->handled;
}

struct test_case {
	const char *name;
	long (*op)(struct result *);
	enum finish finish;
	int (*check)(const struct result *);
};

#define CASE(op, finish, check) { #op, op, finish, check }

#define RUN_CASES(cases, how)                                             \
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {   \
		struct result r = do_run(cases[i].name, cases[i].op, how, \
					 cases[i].finish);                \
		TEST_RES(cases[i].check(&r), _ret);                       \
	}

// No user signal handler runs: the syscalls restart transparently.
static const struct test_case restart_cases[] = {
	CASE(op_nanosleep, FINISH_NONE, timed_out_with_remain),
	CASE(op_clock_nanosleep_abs, FINISH_NONE, timed_out),
	CASE(op_clock_nanosleep_realtime, FINISH_NONE, timed_out_with_remain),
	CASE(op_poll, FINISH_NONE, timed_out),
	CASE(op_ppoll, FINISH_NONE, timed_out_after_stop_with_zero_remain),
	CASE(op_select, FINISH_NONE, timed_out_after_stop),
	CASE(op_pselect6, FINISH_NONE, timed_out_after_stop_with_zero_remain),
	CASE(op_futex_timed, FINISH_NONE, futex_timed_out),
	CASE(op_futex_bitset_abs, FINISH_NONE, futex_timed_out),
	// The syscalls keep waiting until they are finished.
	CASE(op_pause, FINISH_SIGNAL, eintr_handled_late),
	CASE(op_sigsuspend, FINISH_SIGNAL, eintr_handled_late),
	CASE(op_futex, FINISH_FUTEX_WAKE, woken_late),
	CASE(op_read, FINISH_PIPE_WRITE, read_late),
	// `epoll_wait` is never restarted.
	CASE(op_epoll_wait, FINISH_NONE, eintr_unhandled),
};

FN_TEST(restart_after_stop)
{
	RUN_CASES(restart_cases, BY_STOP);
}
END_TEST()

FN_TEST(restart_after_ptrace_interrupt)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	RUN_CASES(restart_cases, BY_PTRACE);
}
END_TEST()

// A user signal handler runs: the syscalls fail with `EINTR`.
static const struct test_case interrupt_cases[] = {
	CASE(op_nanosleep, FINISH_NONE, eintr_handled_with_remain),
	CASE(op_clock_nanosleep_abs, FINISH_NONE, eintr_handled),
	CASE(op_clock_nanosleep_realtime, FINISH_NONE,
	     eintr_handled_with_remain),
	CASE(op_poll, FINISH_NONE, eintr_handled),
	CASE(op_ppoll, FINISH_NONE, eintr_handled_with_remain),
	CASE(op_select, FINISH_NONE, eintr_handled),
	CASE(op_pselect6, FINISH_NONE, eintr_handled_with_remain),
	CASE(op_futex_timed, FINISH_NONE, eintr_handled),
	CASE(op_futex_bitset_abs, FINISH_NONE, eintr_handled),
	CASE(op_epoll_wait, FINISH_NONE, eintr_handled),
	CASE(op_pause, FINISH_NONE, eintr_handled),
	CASE(op_sigsuspend, FINISH_NONE, eintr_handled),
	CASE(op_futex, FINISH_NONE, eintr_handled),
	CASE(op_read, FINISH_NONE, eintr_handled),
};

FN_TEST(interrupt_by_handler)
{
	RUN_CASES(interrupt_cases, BY_HANDLER);
}
END_TEST()

FN_TEST(interrupt_by_handler_after_stop)
{
	RUN_CASES(interrupt_cases, BY_STOP_AND_HANDLER);
}
END_TEST()

// A user signal handler with `SA_RESTART` runs: only the `ERESTARTSYS` class restarts.
static const struct test_case restart_handler_cases[] = {
	CASE(op_nanosleep, FINISH_NONE, eintr_handled_with_remain),
	CASE(op_clock_nanosleep_abs, FINISH_NONE, eintr_handled),
	CASE(op_poll, FINISH_NONE, eintr_handled),
	CASE(op_ppoll, FINISH_NONE, eintr_handled_with_remain),
	CASE(op_select, FINISH_NONE, eintr_handled),
	CASE(op_pselect6, FINISH_NONE, eintr_handled_with_remain),
	CASE(op_futex_timed, FINISH_NONE, eintr_handled),
	CASE(op_futex_bitset_abs, FINISH_NONE, eintr_handled),
	CASE(op_epoll_wait, FINISH_NONE, eintr_handled),
	CASE(op_pause, FINISH_NONE, eintr_handled),
	CASE(op_sigsuspend, FINISH_NONE, eintr_handled),
	CASE(op_futex, FINISH_FUTEX_WAKE, woken_handled),
	CASE(op_read, FINISH_PIPE_WRITE, read_handled),
};

FN_TEST(interrupt_by_restart_handler)
{
	RUN_CASES(restart_handler_cases, BY_RESTART_HANDLER);
}
END_TEST()

#ifdef __x86_64__

#define USER_REG_OFFSET(field) offsetof(struct user_regs_struct, field)

// The kernel-internal errnos that the tracer can see at syscall-exit-stops
#define ERESTARTNOHAND 514
#define ERESTART_RESTARTBLOCK 516

static long op_raw_nanosleep(void)
{
	struct timespec req = { .tv_sec = 0, .tv_nsec = TIMEOUT_MS * 1000000L };

	return syscall(SYS_nanosleep, &req, NULL);
}

static long op_raw_select(void)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = TIMEOUT_MS * 1000L };

	return syscall(SYS_select, 0, NULL, NULL, NULL, &tv);
}

// Returns whether the tracer sees the restart errno at the syscall-exit-stop of the interrupted
// syscall and then sees the syscall entry of `restart_nr`, and whether the tracee completes the
// syscall without seeing the restart errno.
static int trace_restart(long (*op)(void), long nr, long restart_errno,
			 long restart_nr)
{
	int status, in_syscall = 0, state = 0, sig = 0;

	pid_t pid = CHECK(fork());
	if (pid == 0) {
		CHECK(ptrace(PTRACE_TRACEME, 0, 0, 0));
		CHECK(raise(SIGSTOP));
		_exit(op() == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	CHECK_WITH(waitpid(pid, &status, 0),
		   _ret == pid && WIFSTOPPED(status) &&
			   WSTOPSIG(status) == SIGSTOP);
	CHECK(ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD));

	for (;;) {
		CHECK(ptrace(PTRACE_SYSCALL, pid, 0, sig));
		sig = 0;

		if (state == 1) {
			// The tracee is in the syscall to interrupt.
			sleep_ms(INTERRUPT_AT_MS);
			CHECK(kill(pid, SIGUSR2));
		}

		CHECK_WITH(waitpid(pid, &status, 0), _ret == pid);
		if (WIFEXITED(status))
			break;
		CHECK_WITH(status, WIFSTOPPED(status));

		if (WSTOPSIG(status) != (SIGTRAP | 0x80)) {
			// Suppress `SIGUSR2`, so no user signal handler runs.
			if (WSTOPSIG(status) != SIGUSR2)
				sig = WSTOPSIG(status);
			continue;
		}

		in_syscall = !in_syscall;
		long orig_rax = CHECK(ptrace(PTRACE_PEEKUSER, pid,
					     USER_REG_OFFSET(orig_rax), 0));
		long rax =
			ptrace(PTRACE_PEEKUSER, pid, USER_REG_OFFSET(rax), 0);

		if (state == 0 && in_syscall && orig_rax == nr)
			state = 1;
		else if (state == 1 && !in_syscall && rax == -restart_errno)
			state = 2;
		else if (state == 2 && in_syscall && orig_rax == restart_nr)
			state = 3;
	}

	return state == 3 && WEXITSTATUS(status) == EXIT_SUCCESS;
}

FN_TEST(restart_seen_by_tracer)
{
	SKIP_TEST_IF(read_yama_scope() == YAMA_SCOPE_NO_ATTACH);

	TEST_RES(trace_restart(op_raw_nanosleep, SYS_nanosleep,
			       ERESTART_RESTARTBLOCK, SYS_restart_syscall),
		 _ret);
	TEST_RES(trace_restart(op_raw_select, SYS_select, ERESTARTNOHAND,
			       SYS_select),
		 _ret);
}
END_TEST()

#endif
