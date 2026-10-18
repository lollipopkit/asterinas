// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <fcntl.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "../../common/test.h"

#define F_HIPRI 0x01
#define F_DSYNC 0x02
#define F_SYNC 0x04
#define F_NOWAIT 0x08
#define F_APPEND 0x10
#define F_NOAPPEND 0x20
#define F_ATOMIC 0x40
#define F_DONTCACHE 0x80
#define F_NOSIGNAL 0x100
#define F_UNKNOWN 0x200

#define FILE_PATH "/tmp/rwf_flags_file"
#define FIFO_PATH "/tmp/rwf_flags_fifo"

static char buf[256];

static ssize_t do_preadv2(int fd, void *data, size_t len, off_t offset,
			  int flags)
{
	struct iovec iov = { .iov_base = data, .iov_len = len };

	return syscall(SYS_preadv2, fd, &iov, 1, offset, 0, flags);
}

static ssize_t do_pwritev2(int fd, const void *data, size_t len, off_t offset,
			   int flags)
{
	struct iovec iov = { .iov_base = (void *)data, .iov_len = len };

	return syscall(SYS_pwritev2, fd, &iov, 1, offset, 0, flags);
}

static int new_file(int flags)
{
	int fd;

	fd = CHECK(open(FILE_PATH, O_RDWR | O_CREAT | O_TRUNC | flags, 0600));
	CHECK_WITH(write(fd, "0123456789", 10), _ret == 10);
	CHECK(lseek(fd, 2, SEEK_SET));

	return fd;
}

static int read_all(char *data)
{
	int fd, len;

	fd = CHECK(open(FILE_PATH, O_RDONLY));
	len = CHECK(read(fd, data, sizeof(buf)));
	CHECK(close(fd));

	return len;
}

// Returns whether the kernel supports `RWF_NOAPPEND` (Linux 6.9 and later),
// which also supports `RWF_NOWAIT` for timerfd and signalfd files.
static int has_noappend(void)
{
	int fd, ret;

	fd = new_file(0);
	ret = do_pwritev2(fd, "a", 1, 0, F_NOAPPEND);
	CHECK(close(fd));

	return ret == 1;
}

// Returns whether the kernel supports `RWF_NOSIGNAL` (Linux 6.18 and later).
static int has_nosignal(void)
{
	int fd, ret;

	fd = new_file(0);
	ret = do_pwritev2(fd, "a", 1, 0, F_NOSIGNAL);
	CHECK(close(fd));

	return ret == 1;
}

FN_TEST(invalid_flags)
{
	int fd, rdonly;

	fd = new_file(0);

	// Unknown flags are rejected.
	TEST_ERRNO(do_preadv2(fd, buf, 1, 0, F_UNKNOWN), EOPNOTSUPP);
	TEST_ERRNO(do_pwritev2(fd, "a", 1, 0, F_UNKNOWN), EOPNOTSUPP);
	TEST_ERRNO(do_pwritev2(fd, "a", 1, -1, 0x80000000), EOPNOTSUPP);

	// Like Linux, the flags are not checked if there are no data.
	TEST_RES(do_preadv2(fd, buf, 0, 0, F_UNKNOWN), _ret == 0);
	TEST_RES(do_pwritev2(fd, "a", 0, -1, F_UNKNOWN), _ret == 0);

	// Bad files are reported before the flags.
	TEST_ERRNO(do_pwritev2(-1, "a", 1, 0, F_UNKNOWN), EBADF);
	rdonly = TEST_SUCC(open(FILE_PATH, O_RDONLY));
	TEST_ERRNO(do_pwritev2(rdonly, "a", 1, 0, F_UNKNOWN), EBADF);
	TEST_ERRNO(do_pwritev2(rdonly, "a", 1, -1, F_UNKNOWN), EBADF);
	TEST_SUCC(close(rdonly));

	// Atomic writes and uncached I/O are not supported for this file.
	TEST_ERRNO(do_preadv2(fd, buf, 1, 0, F_ATOMIC), EOPNOTSUPP);
	TEST_ERRNO(do_pwritev2(fd, "a", 1, 0, F_ATOMIC), EOPNOTSUPP);
	TEST_ERRNO(do_pwritev2(fd, "a", 1, 0, F_DONTCACHE), EOPNOTSUPP);

	TEST_RES(read_all(buf),
		 _ret == 10 && memcmp(buf, "0123456789", 10) == 0);

	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(append)
{
	int fd;

	fd = new_file(0);

	// `RWF_APPEND` writes at the end, and the file offset is updated only
	// for the current offset.
	TEST_RES(do_pwritev2(fd, "a", 1, 0, F_APPEND), _ret == 1);
	TEST_RES(lseek(fd, 0, SEEK_CUR), _ret == 2);
	TEST_RES(do_pwritev2(fd, "b", 1, -1, F_APPEND), _ret == 1);
	TEST_RES(lseek(fd, 0, SEEK_CUR), _ret == 12);
	TEST_RES(read_all(buf),
		 _ret == 12 && memcmp(buf, "0123456789ab", 12) == 0);

	// Other flags for reads are ignored.
	TEST_RES(do_preadv2(fd, buf, 2, 0, F_APPEND | F_DSYNC | F_HIPRI),
		 _ret == 2 && memcmp(buf, "01", 2) == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(noappend)
{
	int fd;

	SKIP_TEST_IF(!has_noappend());

	// `RWF_APPEND` and `RWF_NOAPPEND` cannot be used together.
	fd = new_file(0);
	TEST_ERRNO(do_pwritev2(fd, "a", 1, 0, F_APPEND | F_NOAPPEND), EINVAL);
	TEST_ERRNO(do_preadv2(fd, buf, 1, 0, F_APPEND | F_NOAPPEND), EINVAL);
	TEST_SUCC(close(fd));

	// `RWF_NOAPPEND` ignores `O_APPEND`.
	fd = new_file(O_APPEND);
	TEST_RES(do_pwritev2(fd, "a", 1, 0, F_NOAPPEND), _ret == 1);
	TEST_RES(do_pwritev2(fd, "b", 1, -1, F_NOAPPEND), _ret == 1);
	TEST_RES(lseek(fd, 0, SEEK_CUR), _ret == 3);
	TEST_RES(do_pwritev2(fd, "c", 1, 1, 0), _ret == 1);
	TEST_RES(read_all(buf),
		 _ret == 11 && memcmp(buf, "a1b3456789c", 11) == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(sync_flags)
{
	int fd;

	fd = new_file(0);
	TEST_RES(do_pwritev2(fd, "a", 1, 0, F_DSYNC), _ret == 1);
	TEST_RES(do_pwritev2(fd, "b", 1, 1, F_SYNC), _ret == 1);
	TEST_RES(do_pwritev2(fd, "c", 1, -1, F_HIPRI | F_SYNC), _ret == 1);
	TEST_RES(read_all(buf),
		 _ret == 10 && memcmp(buf, "abc3456789", 10) == 0);
	TEST_SUCC(close(fd));
	TEST_SUCC(unlink(FILE_PATH));
}
END_TEST()

FN_TEST(nowait_pipe)
{
	int fds[2], fifo;

	TEST_SUCC(pipe(fds));

	// Pipes are blocking, but `RWF_NOWAIT` makes the operations fail with
	// `EAGAIN`.
	TEST_ERRNO(do_preadv2(fds[0], buf, 1, -1, F_NOWAIT), EAGAIN);
	TEST_RES(do_pwritev2(fds[1], "ab", 2, -1, F_NOWAIT), _ret == 2);
	TEST_RES(do_preadv2(fds[0], buf, 1, -1, F_NOWAIT),
		 _ret == 1 && buf[0] == 'a');
	TEST_SUCC(fcntl(fds[1], F_SETFL, O_NONBLOCK));
	while (write(fds[1], buf, sizeof(buf)) > 0)
		;
	while (write(fds[1], buf, 1) > 0)
		;
	TEST_SUCC(fcntl(fds[1], F_SETFL, 0));
	TEST_ERRNO(do_pwritev2(fds[1], buf, 1, -1, F_NOWAIT), EAGAIN);

	// Positional I/O fails with `ESPIPE` before the flags are checked.
	TEST_ERRNO(do_preadv2(fds[0], buf, 1, 0, F_UNKNOWN), ESPIPE);
	TEST_ERRNO(do_pwritev2(fds[1], buf, 1, 0, F_NOWAIT), ESPIPE);

	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));

	// Like Linux, named pipes do not support `RWF_NOWAIT`.
	TEST_SUCC(mkfifo(FIFO_PATH, 0600));
	fifo = TEST_SUCC(open(FIFO_PATH, O_RDWR));
	TEST_ERRNO(do_preadv2(fifo, buf, 1, -1, F_NOWAIT), EOPNOTSUPP);
	TEST_RES(do_pwritev2(fifo, "a", 1, -1, F_DSYNC), _ret == 1);
	TEST_RES(do_preadv2(fifo, buf, 1, -1, F_HIPRI), _ret == 1);
	TEST_SUCC(close(fifo));
	TEST_SUCC(unlink(FIFO_PATH));
}
END_TEST()

FN_TEST(nowait_socket)
{
	int fds[2];

	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
	TEST_ERRNO(do_preadv2(fds[0], buf, 1, -1, F_NOWAIT), EAGAIN);
	TEST_RES(do_pwritev2(fds[1], "a", 1, -1, F_NOWAIT), _ret == 1);
	TEST_RES(do_preadv2(fds[0], buf, 1, -1, F_NOWAIT), _ret == 1);
	TEST_ERRNO(do_preadv2(fds[0], buf, 1, 0, F_NOWAIT), ESPIPE);
	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()

FN_TEST(nowait_eventfd)
{
	uint64_t val = 1;
	int fd;

	// `eventfd` supports `RWF_NOWAIT` for reads. Its writes do not support
	// any flags except `RWF_HIPRI`.
	fd = TEST_SUCC(eventfd(0, 0));
	TEST_ERRNO(do_preadv2(fd, &val, sizeof(val), -1, F_NOWAIT), EAGAIN);
	TEST_ERRNO(do_pwritev2(fd, &val, sizeof(val), -1, F_NOWAIT),
		   EOPNOTSUPP);
	TEST_ERRNO(do_pwritev2(fd, &val, sizeof(val), -1, F_DSYNC), EOPNOTSUPP);
	TEST_RES(do_pwritev2(fd, &val, sizeof(val), -1, F_HIPRI),
		 _ret == sizeof(val));
	TEST_RES(do_preadv2(fd, &val, sizeof(val), -1, F_NOWAIT),
		 _ret == sizeof(val) && val == 1);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(nowait_timerfd_signalfd)
{
	struct itimerspec its = {};
	uint64_t val;
	sigset_t set;
	int fd;

	SKIP_TEST_IF(!has_noappend());

	fd = TEST_SUCC(timerfd_create(CLOCK_MONOTONIC, 0));
	TEST_SUCC(timerfd_settime(fd, 0, &its, NULL));
	TEST_ERRNO(do_preadv2(fd, &val, sizeof(val), -1, F_NOWAIT), EAGAIN);
	TEST_SUCC(close(fd));

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	fd = TEST_SUCC(signalfd(-1, &set, 0));
	TEST_ERRNO(do_preadv2(fd, buf, sizeof(struct signalfd_siginfo), -1,
			      F_NOWAIT),
		   EAGAIN);
	TEST_SUCC(close(fd));
}
END_TEST()

static int take_sigpipe(void)
{
	struct timespec timeout = { 0, 0 };
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	return sigtimedwait(&set, NULL, &timeout);
}

FN_TEST(nosignal)
{
	sigset_t set, old_set;
	int fds[2];

	SKIP_TEST_IF(!has_nosignal());

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	TEST_SUCC(sigprocmask(SIG_BLOCK, &set, &old_set));

	// `RWF_NOSIGNAL` suppresses `SIGPIPE` for pipes and sockets.
	TEST_SUCC(pipe(fds));
	TEST_SUCC(close(fds[0]));
	TEST_ERRNO(do_pwritev2(fds[1], "a", 1, -1, F_NOSIGNAL), EPIPE);
	TEST_ERRNO(take_sigpipe(), EAGAIN);
	TEST_ERRNO(do_pwritev2(fds[1], "a", 1, -1, 0), EPIPE);
	TEST_RES(take_sigpipe(), _ret == SIGPIPE);
	TEST_SUCC(close(fds[1]));

	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
	TEST_SUCC(close(fds[0]));
	TEST_ERRNO(do_pwritev2(fds[1], "a", 1, -1, F_NOSIGNAL), EPIPE);
	TEST_ERRNO(take_sigpipe(), EAGAIN);
	TEST_ERRNO(do_pwritev2(fds[1], "a", 1, -1, 0), EPIPE);
	TEST_RES(take_sigpipe(), _ret == SIGPIPE);
	TEST_SUCC(close(fds[1]));

	TEST_SUCC(sigprocmask(SIG_SETMASK, &old_set, NULL));
	TEST_SUCC(unlink(FILE_PATH));
}
END_TEST()
