// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../common/test.h"

static const struct sockaddr unspec_addr = { .sa_family = AF_UNSPEC };
#define UNSPEC_LEN sizeof(sa_family_t)

static struct sockaddr_in loopback_addr;
static struct sockaddr_in listen_addr;
static int listener;

#define BOUND_PORT htons(0x4567)

static int new_tcp_socket(void)
{
	int sk, one = 1;

	sk = CHECK(socket(PF_INET, SOCK_STREAM, 0));
	CHECK(setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));

	return sk;
}

static int new_listener(struct sockaddr_in *addr)
{
	socklen_t addrlen = sizeof(*addr);
	int sk;

	sk = new_tcp_socket();
	CHECK(bind(sk, (struct sockaddr *)addr, sizeof(*addr)));
	CHECK(getsockname(sk, (struct sockaddr *)addr, &addrlen));
	CHECK(listen(sk, 4));

	return sk;
}

FN_SETUP(listener)
{
	loopback_addr.sin_family = AF_INET;
	CHECK(inet_aton("127.0.0.1", &loopback_addr.sin_addr));

	listen_addr = loopback_addr;
	listener = new_listener(&listen_addr);
}
END_SETUP()

// Connects `sk` to the listener and returns the accepted socket.
static int connect_and_accept(int sk)
{
	CHECK(connect(sk, (struct sockaddr *)&listen_addr,
		      sizeof(listen_addr)));
	return CHECK(accept(listener, NULL, NULL));
}

#define WAIT_EVENTS(sk, mask)                                         \
	do {                                                          \
		struct pollfd __pfd = { .fd = sk, .events = (mask) }; \
		TEST_RES(poll(&__pfd, 1, 1000), _ret == 1);             \
	} while (0)

#define CHECK_SO_ERROR(sk, expected)                                     \
	do {                                                             \
		int __err;                                               \
		socklen_t __errlen = sizeof(__err);                      \
		TEST_RES(getsockopt(sk, SOL_SOCKET, SO_ERROR, &__err,    \
				    &__errlen),                          \
			 __errlen == sizeof(__err) && __err == expected); \
	} while (0)

#define CHECK_SOCKNAME(sk, addr, port)                                       \
	do {                                                                 \
		struct sockaddr_in __name;                                   \
		socklen_t __namelen = sizeof(__name);                        \
		TEST_RES(getsockname(sk, (struct sockaddr *)&__name,         \
				     &__namelen),                            \
			 __namelen == sizeof(__name) &&                      \
				 __name.sin_addr.s_addr == (addr) &&         \
				 __name.sin_port == (port));                 \
	} while (0)

#define CHECK_NO_PEER(sk)                                              \
	do {                                                           \
		struct sockaddr_in __peer;                             \
		socklen_t __peerlen = sizeof(__peer);                  \
		TEST_ERRNO(getpeername(sk, (struct sockaddr *)&__peer, \
				       &__peerlen),                    \
			   ENOTCONN);                                  \
	} while (0)

FN_TEST(disconnect_connected)
{
	char buf[2];
	int sk, peer;

	sk = new_tcp_socket();
	peer = connect_and_accept(sk);
	TEST_RES(send(peer, "a", 1, 0), _ret == 1);

	// The connection is reset, which discards the received data.
	TEST_SUCC(connect(sk, &unspec_addr, UNSPEC_LEN));
	CHECK_NO_PEER(sk);
	WAIT_EVENTS(peer, POLLIN);
	TEST_ERRNO(recv(peer, buf, sizeof(buf), 0), ECONNRESET);
	TEST_SUCC(close(peer));

	// The reset is reported once, then the socket is unconnected.
	TEST_RES(poll(&(struct pollfd){ .fd = sk, .events = POLLIN | POLLOUT },
		      1, 0),
		 _ret == 1);
	CHECK_SO_ERROR(sk, ECONNRESET);
	CHECK_SO_ERROR(sk, 0);
	TEST_ERRNO(recv(sk, buf, sizeof(buf), MSG_DONTWAIT), ENOTCONN);
	TEST_ERRNO(send(sk, "b", 1, MSG_NOSIGNAL), EPIPE);

	// Disconnecting again does nothing.
	TEST_SUCC(connect(sk, &unspec_addr, UNSPEC_LEN));
	CHECK_SO_ERROR(sk, 0);

	// The socket can connect again.
	peer = connect_and_accept(sk);
	TEST_RES(send(sk, "c", 1, 0), _ret == 1);
	TEST_RES(recv(peer, buf, sizeof(buf), 0), _ret == 1 && buf[0] == 'c');

	TEST_SUCC(close(peer));
	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(disconnect_reset_reported)
{
	char buf[2];
	int sk, peer;

	sk = new_tcp_socket();
	peer = connect_and_accept(sk);

	// A reset that has not been reported is still reported after disconnecting.
	TEST_SUCC(setsockopt(peer, SOL_SOCKET, SO_LINGER,
			     &(struct linger){ .l_onoff = 1, .l_linger = 0 },
			     sizeof(struct linger)));
	TEST_SUCC(close(peer));
	WAIT_EVENTS(sk, POLLERR);
	TEST_SUCC(connect(sk, &unspec_addr, UNSPEC_LEN));
	TEST_ERRNO(recv(sk, buf, sizeof(buf), MSG_DONTWAIT), ECONNRESET);
	TEST_ERRNO(recv(sk, buf, sizeof(buf), MSG_DONTWAIT), ENOTCONN);

	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(disconnect_closed)
{
	char buf[2];
	int sk, peer;

	sk = new_tcp_socket();
	peer = connect_and_accept(sk);

	// A connection closed by both sides is not reset.
	TEST_SUCC(shutdown(sk, SHUT_WR));
	TEST_RES(recv(peer, buf, sizeof(buf), 0), _ret == 0);
	TEST_SUCC(close(peer));
	TEST_RES(recv(sk, buf, sizeof(buf), 0), _ret == 0);
	TEST_SUCC(connect(sk, &unspec_addr, UNSPEC_LEN));
	CHECK_SO_ERROR(sk, 0);
	TEST_ERRNO(recv(sk, buf, sizeof(buf), MSG_DONTWAIT), ENOTCONN);

	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(disconnect_auto_bound)
{
	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	int sk, sk2, peer;

	sk = new_tcp_socket();
	peer = connect_and_accept(sk);
	TEST_SUCC(getsockname(sk, (struct sockaddr *)&name, &namelen));
	TEST_SUCC(connect(sk, &unspec_addr, UNSPEC_LEN));
	TEST_SUCC(close(peer));

	// The automatically bound port is released.
	sk2 = CHECK(socket(PF_INET, SOCK_STREAM, 0));
	TEST_SUCC(bind(sk2, (struct sockaddr *)&name, sizeof(name)));
	TEST_SUCC(close(sk2));

	// The socket can be bound again.
	TEST_SUCC(bind(sk, (struct sockaddr *)&name, sizeof(name)));
	CHECK_SOCKNAME(sk, name.sin_addr.s_addr, name.sin_port);

	TEST_SUCC(close(sk));
}
END_TEST()

// Tests a socket bound to `bind_addr` and a specified port.
#define TEST_DISCONNECT_BOUND_PORT(bind_addr)                                 \
	do {                                                                  \
		struct sockaddr_in __addr = { .sin_family = AF_INET,          \
					      .sin_port = BOUND_PORT,         \
					      .sin_addr.s_addr = bind_addr }; \
		char __buf[2];                                                \
		int __sk, __sk2, __peer;                                      \
                                                                              \
		__sk = new_tcp_socket();                                      \
		CHECK(bind(__sk, (struct sockaddr *)&__addr, sizeof(__addr))); \
		__peer = connect_and_accept(__sk);                            \
		TEST_SUCC(connect(__sk, &unspec_addr, UNSPEC_LEN));           \
		TEST_SUCC(close(__peer));                                     \
                                                                              \
		/* The address and the port specified by `bind` are kept. */  \
		CHECK_SOCKNAME(__sk, bind_addr, BOUND_PORT);                  \
		TEST_ERRNO(bind(__sk, (struct sockaddr *)&__addr,             \
				sizeof(__addr)),                              \
			   EINVAL);                                           \
		__sk2 = CHECK(socket(PF_INET, SOCK_STREAM, 0));               \
		TEST_ERRNO(bind(__sk2, (struct sockaddr *)&__addr,            \
				sizeof(__addr)),                              \
			   EADDRINUSE);                                       \
		TEST_SUCC(close(__sk2));                                      \
                                                                              \
		/* The socket can connect again from the same port. */        \
		__peer = connect_and_accept(__sk);                            \
		CHECK_SOCKNAME(__sk, loopback_addr.sin_addr.s_addr,           \
			       BOUND_PORT);                                   \
		TEST_RES(send(__peer, "d", 1, 0), _ret == 1);                 \
		TEST_RES(recv(__sk, __buf, sizeof(__buf), 0),                 \
			 _ret == 1 && __buf[0] == 'd');                       \
                                                                              \
		TEST_SUCC(close(__peer));                                     \
		TEST_SUCC(close(__sk));                                       \
	} while (0)

FN_TEST(disconnect_bound_port)
{
	TEST_DISCONNECT_BOUND_PORT(loopback_addr.sin_addr.s_addr);
}
END_TEST()

FN_TEST(disconnect_bound_port_any_addr)
{
	TEST_DISCONNECT_BOUND_PORT(htonl(INADDR_ANY));
}
END_TEST()

FN_TEST(disconnect_listening)
{
	struct sockaddr_in addr = { .sin_family = AF_INET,
				    .sin_port = BOUND_PORT,
				    .sin_addr = loopback_addr.sin_addr };
	char buf[2];
	int sk, client, client2, peer;

	sk = new_listener(&addr);
	client = new_tcp_socket();
	TEST_SUCC(connect(client, (struct sockaddr *)&addr, sizeof(addr)));

	// Pending connections are reset.
	TEST_SUCC(connect(sk, &unspec_addr, UNSPEC_LEN));
	WAIT_EVENTS(client, POLLIN);
	TEST_ERRNO(recv(client, buf, sizeof(buf), 0), ECONNRESET);
	CHECK_SO_ERROR(sk, 0);

	// The socket stops listening, but the bound address is kept.
	TEST_ERRNO(accept4(sk, NULL, NULL, SOCK_NONBLOCK), EINVAL);
	CHECK_SOCKNAME(sk, addr.sin_addr.s_addr, BOUND_PORT);
	client2 = new_tcp_socket();
	TEST_ERRNO(connect(client2, (struct sockaddr *)&addr, sizeof(addr)),
		   ECONNREFUSED);
	TEST_SUCC(close(client2));

	// The socket can listen again.
	TEST_SUCC(listen(sk, 1));
	client2 = new_tcp_socket();
	TEST_SUCC(connect(client2, (struct sockaddr *)&addr, sizeof(addr)));
	peer = TEST_SUCC(accept(sk, NULL, NULL));

	TEST_SUCC(close(peer));
	TEST_SUCC(close(client2));
	TEST_SUCC(close(client));
	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(disconnect_listening_auto_bound)
{
	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	int sk, sk2;

	sk = new_tcp_socket();
	TEST_SUCC(listen(sk, 1));
	TEST_SUCC(getsockname(sk, (struct sockaddr *)&name, &namelen));

	// The automatically bound port is released.
	TEST_SUCC(connect(sk, &unspec_addr, UNSPEC_LEN));
	sk2 = CHECK(socket(PF_INET, SOCK_STREAM, 0));
	TEST_SUCC(bind(sk2, (struct sockaddr *)&name, sizeof(name)));
	TEST_SUCC(close(sk2));

	TEST_SUCC(close(sk));
}
END_TEST()

struct blocked_op {
	int sk;
	int ret;
	int err;
};

static void *blocked_accept(void *arg)
{
	struct blocked_op *op = arg;

	op->ret = accept(op->sk, NULL, NULL);
	op->err = errno;
	return NULL;
}

static void *blocked_recv(void *arg)
{
	struct blocked_op *op = arg;
	char buf[2];

	op->ret = recv(op->sk, buf, sizeof(buf), 0);
	op->err = errno;
	return NULL;
}

// Runs `func` in another thread and disconnects the socket while it is blocked.
#define TEST_DISCONNECT_BLOCKED(fd, func, expected)                          \
	do {                                                                 \
		struct blocked_op __op = { .sk = (fd) };                     \
		pthread_t __tid;                                          \
                                                                             \
		TEST_SUCC(pthread_create(&__tid, NULL, func, &__op));     \
		usleep(200 * 1000);                                          \
		TEST_SUCC(connect(fd, &unspec_addr, UNSPEC_LEN));            \
		TEST_SUCC(pthread_join(__tid, NULL));                     \
		TEST_RES(__op.ret, __op.ret == -1 && __op.err == (expected)); \
	} while (0)

FN_TEST(disconnect_blocked)
{
	struct sockaddr_in addr = loopback_addr;
	int sk, peer;

	// A blocked `accept` fails because the socket is no longer listening.
	sk = new_listener(&addr);
	TEST_DISCONNECT_BLOCKED(sk, blocked_accept, EINVAL);
	TEST_SUCC(close(sk));

	// A blocked `recv` fails because the socket is disconnected, and the reset is still
	// reported later.
	sk = new_tcp_socket();
	peer = connect_and_accept(sk);
	TEST_DISCONNECT_BLOCKED(sk, blocked_recv, EPIPE);
	CHECK_SO_ERROR(sk, ECONNRESET);
	CHECK_SO_ERROR(sk, 0);
	TEST_SUCC(close(peer));
	TEST_SUCC(close(sk));
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(close(listener));
}
END_SETUP()
