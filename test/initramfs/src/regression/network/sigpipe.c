// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "../common/test.h"

static struct sockaddr_in listen_addr;
static int tcp_listener;

FN_SETUP(block_sigpipe)
{
	sigset_t set;

	// Keep `SIGPIPE` pending so that it can be checked with `sigtimedwait`.
	CHECK(sigemptyset(&set));
	CHECK(sigaddset(&set, SIGPIPE));
	CHECK(sigprocmask(SIG_BLOCK, &set, NULL));
}
END_SETUP()

FN_SETUP(tcp_listener)
{
	socklen_t addrlen = sizeof(listen_addr);

	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	listen_addr.sin_port = 0;

	tcp_listener = CHECK(socket(AF_INET, SOCK_STREAM, 0));
	CHECK(bind(tcp_listener, (struct sockaddr *)&listen_addr,
		   sizeof(listen_addr)));
	CHECK(getsockname(tcp_listener, (struct sockaddr *)&listen_addr,
			  &addrlen));
	CHECK(listen(tcp_listener, 4));
}
END_SETUP()

static void new_tcp_pair(int *client, int *server)
{
	*client = CHECK(socket(AF_INET, SOCK_STREAM, 0));
	CHECK(connect(*client, (struct sockaddr *)&listen_addr,
		      sizeof(listen_addr)));
	*server = CHECK(accept(tcp_listener, NULL, NULL));
}

// Takes a pending `SIGPIPE` without blocking. Returns `SIGPIPE` or fails with
// `EAGAIN`.
static int take_sigpipe(siginfo_t *info)
{
	struct timespec timeout = { 0, 0 };
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	return sigtimedwait(&set, info, &timeout);
}

// Like Linux's `send_sig(SIGPIPE, current, 0)`, the signal carries `SI_USER`
// with the PID and the real UID of the sender.
#define TEST_SIGPIPE()                                                    \
	do {                                                              \
		siginfo_t __info;                                         \
		TEST_RES(take_sigpipe(&__info),                           \
			 _ret == SIGPIPE && __info.si_signo == SIGPIPE && \
				 __info.si_code == SI_USER &&             \
				 __info.si_pid == getpid() &&             \
				 __info.si_uid == getuid());              \
	} while (0)

#define TEST_NO_SIGPIPE()                                  \
	do {                                               \
		siginfo_t __info;                          \
		TEST_ERRNO(take_sigpipe(&__info), EAGAIN); \
	} while (0)

// Tests every send operation on `sk`, which must fail with `EPIPE`.
#define TEST_SEND_OPS(sk, has_sigpipe)                                        \
	do {                                                                  \
		struct iovec __iov = { .iov_base = "x", .iov_len = 1 };       \
		struct msghdr __msg = { .msg_iov = &__iov, .msg_iovlen = 1 }; \
                                                                              \
		TEST_ERRNO(send(sk, "x", 1, 0), EPIPE);                       \
		if (has_sigpipe)                                              \
			TEST_SIGPIPE();                                       \
		TEST_NO_SIGPIPE();                                            \
                                                                              \
		TEST_ERRNO(write(sk, "x", 1), EPIPE);                         \
		if (has_sigpipe)                                              \
			TEST_SIGPIPE();                                       \
		TEST_NO_SIGPIPE();                                            \
                                                                              \
		TEST_ERRNO(writev(sk, &__iov, 1), EPIPE);                     \
		if (has_sigpipe)                                              \
			TEST_SIGPIPE();                                       \
		TEST_NO_SIGPIPE();                                            \
                                                                              \
		TEST_ERRNO(sendto(sk, "x", 1, 0, NULL, 0), EPIPE);            \
		if (has_sigpipe)                                              \
			TEST_SIGPIPE();                                       \
		TEST_NO_SIGPIPE();                                            \
                                                                              \
		TEST_ERRNO(sendmsg(sk, &__msg, 0), EPIPE);                    \
		if (has_sigpipe)                                              \
			TEST_SIGPIPE();                                       \
		TEST_NO_SIGPIPE();                                            \
                                                                              \
		TEST_ERRNO(send(sk, "x", 1, MSG_NOSIGNAL), EPIPE);            \
		TEST_ERRNO(sendmsg(sk, &__msg, MSG_NOSIGNAL), EPIPE);         \
		TEST_ERRNO(send(sk, "x", 1, MSG_NOSIGNAL | MSG_DONTWAIT),     \
			   EPIPE);                                            \
		TEST_NO_SIGPIPE();                                            \
	} while (0)

FN_TEST(tcp_shut_wr)
{
	int client, server;

	new_tcp_pair(&client, &server);

	TEST_SUCC(shutdown(client, SHUT_WR));
	TEST_SEND_OPS(client, 1);

	TEST_SUCC(close(client));
	TEST_SUCC(close(server));
}
END_TEST()

FN_TEST(tcp_unconnected)
{
	int sk;

	// Like Linux, sending on a TCP socket that is not connected fails with
	// `EPIPE` instead of `ENOTCONN`.
	sk = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SEND_OPS(sk, 1);
	TEST_SUCC(close(sk));

	TEST_SEND_OPS(tcp_listener, 1);
}
END_TEST()

FN_TEST(tcp_peer_closed)
{
	struct pollfd pfd;
	int client, server;
	int err;
	socklen_t errlen = sizeof(err);
	char buf[1];

	new_tcp_pair(&client, &server);
	TEST_SUCC(close(server));

	// The peer has sent a FIN, so the first send succeeds. Then the peer
	// replies with a RST.
	TEST_RES(send(client, "x", 1, 0), _ret == 1);
	pfd.fd = client;
	pfd.events = 0;
	TEST_RES(poll(&pfd, 1, 1000), _ret == 1 && (pfd.revents & POLLERR));
	TEST_NO_SIGPIPE();

	// Like Linux, a RST in the `CLOSE-WAIT` state breaks the pipe. The end
	// of the stream is reported before the error.
	TEST_RES(recv(client, buf, sizeof(buf), 0), _ret == 0);
	TEST_ERRNO(send(client, "x", 1, 0), EPIPE);
	TEST_SIGPIPE();
	TEST_SEND_OPS(client, 1);
	TEST_RES(getsockopt(client, SOL_SOCKET, SO_ERROR, &err, &errlen),
		 err == 0);

	TEST_SUCC(close(client));
}
END_TEST()

FN_TEST(tcp_peer_closed_so_error)
{
	struct pollfd pfd;
	int client, server;
	int err;
	socklen_t errlen = sizeof(err);

	new_tcp_pair(&client, &server);
	TEST_SUCC(close(server));

	TEST_RES(send(client, "x", 1, 0), _ret == 1);
	pfd.fd = client;
	pfd.events = 0;
	TEST_RES(poll(&pfd, 1, 1000), _ret == 1 && (pfd.revents & POLLERR));

	// The pending error is `EPIPE`, which is cleared after it is reported.
	TEST_RES(getsockopt(client, SOL_SOCKET, SO_ERROR, &err, &errlen),
		 err == EPIPE);
	TEST_RES(getsockopt(client, SOL_SOCKET, SO_ERROR, &err, &errlen),
		 err == 0);
	TEST_SEND_OPS(client, 1);

	TEST_SUCC(close(client));
}
END_TEST()

FN_TEST(tcp_reset)
{
	struct linger linger = { .l_onoff = 1, .l_linger = 0 };
	struct pollfd pfd;
	int client, server;

	new_tcp_pair(&client, &server);

	// The RST arrives in the `ESTABLISHED` state. Like Linux, the first
	// error is `ECONNRESET` without `SIGPIPE`.
	TEST_SUCC(setsockopt(server, SOL_SOCKET, SO_LINGER, &linger,
			     sizeof(linger)));
	TEST_SUCC(close(server));
	pfd.fd = client;
	pfd.events = 0;
	TEST_RES(poll(&pfd, 1, 1000), _ret == 1 && (pfd.revents & POLLERR));

	TEST_ERRNO(send(client, "x", 1, 0), ECONNRESET);
	TEST_NO_SIGPIPE();
	TEST_SEND_OPS(client, 1);

	TEST_SUCC(close(client));
}
END_TEST()

FN_TEST(sendfile_to_socket)
{
	char path[] = "/tmp/sigpipe_sendfile_XXXXXX";
	int client, server, file;

	file = TEST_SUCC(mkstemp(path));
	TEST_SUCC(unlink(path));
	TEST_RES(write(file, "x", 1), _ret == 1);

	new_tcp_pair(&client, &server);
	TEST_SUCC(shutdown(client, SHUT_WR));

	TEST_ERRNO(sendfile(client, file, &(off_t){ 0 }, 1), EPIPE);
	TEST_SIGPIPE();
	TEST_NO_SIGPIPE();

	TEST_SUCC(close(client));
	TEST_SUCC(close(server));
	TEST_SUCC(close(file));
}
END_TEST()

FN_TEST(unix_stream)
{
	int fds[2];

	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
	TEST_SUCC(shutdown(fds[0], SHUT_WR));
	TEST_SEND_OPS(fds[0], 1);
	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));

	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
	TEST_SUCC(shutdown(fds[1], SHUT_RD));
	TEST_SEND_OPS(fds[0], 1);
	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));

	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
	TEST_SUCC(close(fds[1]));
	TEST_SEND_OPS(fds[0], 1);
	TEST_SUCC(close(fds[0]));
}
END_TEST()

FN_TEST(unix_stream_unconnected)
{
	int sk;

	// An unconnected UNIX stream socket fails with `ENOTCONN`.
	sk = TEST_SUCC(socket(AF_UNIX, SOCK_STREAM, 0));
	TEST_ERRNO(send(sk, "x", 1, 0), ENOTCONN);
	TEST_NO_SIGPIPE();
	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(unix_seqpacket)
{
	int fds[2];

	// Like Linux, `SOCK_SEQPACKET` sockets send messages like datagram
	// sockets and do not raise `SIGPIPE`.
	TEST_SUCC(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
	TEST_SUCC(shutdown(fds[0], SHUT_WR));
	TEST_SEND_OPS(fds[0], 0);
	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));

	TEST_SUCC(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
	TEST_SUCC(close(fds[1]));
	TEST_SEND_OPS(fds[0], 0);
	TEST_SUCC(close(fds[0]));
}
END_TEST()

FN_TEST(unix_dgram)
{
	int fds[2];

	TEST_SUCC(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds));
	TEST_SUCC(shutdown(fds[0], SHUT_WR));
	TEST_SEND_OPS(fds[0], 0);
	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()

static int thread_sk;
static int thread_has_sigpipe;
static int thread_send_errno;

static void *send_in_thread(void *arg)
{
	struct timespec timeout = { 0, 0 };
	siginfo_t info;
	sigset_t set;

	(void)arg;

	if (send(thread_sk, "x", 1, 0) < 0)
		thread_send_errno = errno;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	if (sigtimedwait(&set, &info, &timeout) == SIGPIPE &&
	    info.si_code == SI_USER && info.si_pid == getpid())
		thread_has_sigpipe = 1;

	return NULL;
}

FN_TEST(thread_directed)
{
	pthread_t thread;
	sigset_t pending;
	int fds[2];

	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
	TEST_SUCC(shutdown(fds[0], SHUT_WR));
	thread_sk = fds[0];

	// The signal is sent to the thread that sends, not to the process.
	TEST_SUCC(pthread_create(&thread, NULL, send_in_thread, NULL));
	TEST_SUCC(pthread_join(thread, NULL));
	TEST_RES(thread_send_errno, _ret == EPIPE);
	TEST_RES(thread_has_sigpipe, _ret == 1);
	TEST_RES(sigpending(&pending), sigismember(&pending, SIGPIPE) == 0);
	TEST_NO_SIGPIPE();

	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()
