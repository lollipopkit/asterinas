// SPDX-License-Identifier: MPL-2.0

#include <stddef.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>

#include "../common/test.h"

// `AF_UNSPEC` addresses as long as `sa_family_t` and as `struct sockaddr_in`.
static const struct sockaddr unspec_addr = { .sa_family = AF_UNSPEC };
#define UNSPEC_LEN sizeof(sa_family_t)
static struct sockaddr_in unspec_inet;

static struct sockaddr_in loopback_addr;
static struct sockaddr_in peer_addr_a, peer_addr_b;
static int peer_a, peer_b;

#define BOUND_PORT htons(0x2345)

static int new_udp_socket(void)
{
	return CHECK(socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
}

static int new_bound_udp_socket(struct sockaddr_in *addr)
{
	int sk;
	socklen_t addrlen = sizeof(*addr);

	sk = new_udp_socket();
	CHECK(bind(sk, (struct sockaddr *)addr, sizeof(*addr)));
	CHECK(getsockname(sk, (struct sockaddr *)addr, &addrlen));

	return sk;
}

FN_SETUP(peers)
{
	unspec_inet.sin_family = AF_UNSPEC;

	loopback_addr.sin_family = AF_INET;
	CHECK(inet_aton("127.0.0.1", &loopback_addr.sin_addr));

	peer_addr_a = peer_addr_b = loopback_addr;
	peer_a = new_bound_udp_socket(&peer_addr_a);
	peer_b = new_bound_udp_socket(&peer_addr_b);
}
END_SETUP()

#define SEND(sk, buf, to)                                                     \
	TEST_RES(sendto(sk, buf, 1, 0, (struct sockaddr *)&to, sizeof(to)), \
		 _ret == 1)

// Waits for a datagram, since the loopback delivery can be asynchronous.
#define WAIT_READABLE(sk)                                             \
	do {                                                          \
		struct pollfd __pfd = { .fd = sk, .events = POLLIN }; \
		TEST_RES(poll(&__pfd, 1, 1000), _ret == 1);           \
	} while (0)

#define RECV_FROM(sk, from_port, expected)                                     \
	do {                                                                   \
		char __buf[2];                                                 \
		struct sockaddr_in __from;                                     \
		socklen_t __fromlen = sizeof(__from);                          \
		WAIT_READABLE(sk);                                             \
		TEST_RES(recvfrom(sk, __buf, sizeof(__buf), 0,                 \
				  (struct sockaddr *)&__from, &__fromlen),     \
			 _ret == 1 && __buf[0] == expected &&                  \
				 __from.sin_port == (from_port));              \
	} while (0)

#define RECV_NONE(sk)                                                       \
	do {                                                                \
		char __buf[2];                                              \
		TEST_ERRNO(recv(sk, __buf, sizeof(__buf), MSG_DONTWAIT), \
			   EAGAIN);                                         \
	} while (0)

#define CHECK_SOCKNAME(sk, addr, port)                                       \
	do {                                                                 \
		struct sockaddr_in __name;                                   \
		socklen_t __namelen = sizeof(__name);                        \
		TEST_RES(getsockname(sk, (struct sockaddr *)&__name,         \
				     &__namelen),                            \
			 __namelen == sizeof(__name) &&                      \
				 __name.sin_family == AF_INET &&             \
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

// This is checked last, since Linux binds an unbound socket even if sending fails.
#define CHECK_NO_DEST(sk) TEST_ERRNO(send(sk, "x", 1, 0), EDESTADDRREQ)

FN_TEST(udp_disconnect_unbound)
{
	int sk = new_udp_socket();

	// The address must contain at least the family.
	TEST_ERRNO(connect(sk, &unspec_addr, 1), EINVAL);
	TEST_SUCC(connect(sk, &unspec_addr, UNSPEC_LEN));

	// Disconnecting does not bind the socket.
	CHECK_SOCKNAME(sk, htonl(INADDR_ANY), 0);
	CHECK_NO_PEER(sk);

	CHECK_NO_DEST(sk);
	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(udp_disconnect_auto_bound)
{
	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	int sk, sk2;

	sk = new_udp_socket();
	TEST_SUCC(connect(sk, (struct sockaddr *)&peer_addr_a,
			  sizeof(peer_addr_a)));
	TEST_RES(getsockname(sk, (struct sockaddr *)&name, &namelen),
		 name.sin_addr.s_addr == loopback_addr.sin_addr.s_addr &&
			 name.sin_port != 0);

	TEST_SUCC(connect(sk, &unspec_addr, UNSPEC_LEN));
	CHECK_NO_PEER(sk);

	// The automatically bound address and port are released.
	CHECK_SOCKNAME(sk, htonl(INADDR_ANY), 0);
	sk2 = new_udp_socket();
	TEST_SUCC(bind(sk2, (struct sockaddr *)&name, sizeof(name)));
	TEST_SUCC(close(sk2));

	// The socket can be bound again.
	TEST_SUCC(bind(sk, (struct sockaddr *)&name, sizeof(name)));
	CHECK_SOCKNAME(sk, name.sin_addr.s_addr, name.sin_port);

	CHECK_NO_DEST(sk);
	TEST_SUCC(close(sk));
}
END_TEST()

// Tests a socket bound to `bind_addr` and a specified port.
#define TEST_DISCONNECT_BOUND_PORT(bind_addr)                                 \
	do {                                                                  \
		struct sockaddr_in __addr = { .sin_family = AF_INET,          \
					      .sin_port = BOUND_PORT,         \
					      .sin_addr.s_addr = bind_addr }; \
		struct sockaddr_in __to = loopback_addr;                      \
		int __sk;                                                     \
                                                                              \
		__sk = new_bound_udp_socket(&__addr);                         \
		__to.sin_port = BOUND_PORT;                                   \
                                                                              \
		TEST_SUCC(connect(__sk, (struct sockaddr *)&peer_addr_a,      \
				  sizeof(peer_addr_a)));                      \
		SEND(peer_b, "b", __to);                                      \
		SEND(peer_a, "a", __to);                                      \
		RECV_FROM(__sk, peer_addr_a.sin_port, 'a');                   \
		RECV_NONE(__sk);                                              \
                                                                              \
		TEST_SUCC(connect(__sk, &unspec_addr, UNSPEC_LEN));           \
		CHECK_NO_PEER(__sk);                                          \
                                                                              \
		/* The address and the port specified by `bind` are kept. */  \
		CHECK_SOCKNAME(__sk, bind_addr, BOUND_PORT);                  \
                                                                              \
		/* Datagrams from any peer are received again. */             \
		SEND(peer_b, "b", __to);                                      \
		RECV_FROM(__sk, peer_addr_b.sin_port, 'b');                   \
		SEND(peer_a, "a", __to);                                      \
		RECV_FROM(__sk, peer_addr_a.sin_port, 'a');                   \
                                                                              \
		CHECK_NO_DEST(__sk);                                          \
		TEST_SUCC(close(__sk));                                       \
	} while (0)

FN_TEST(udp_disconnect_bound_port)
{
	TEST_DISCONNECT_BOUND_PORT(loopback_addr.sin_addr.s_addr);
}
END_TEST()

// FIXME: Asterinas does not support binding UDP sockets to `INADDR_ANY` yet.
#ifndef __asterinas__
FN_TEST(udp_disconnect_bound_port_any_addr)
{
	TEST_DISCONNECT_BOUND_PORT(htonl(INADDR_ANY));
}
END_TEST()
#endif

FN_TEST(udp_disconnect_bound_addr)
{
	struct sockaddr_in addr = loopback_addr;
	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	int sk;

	sk = new_bound_udp_socket(&addr);
	TEST_SUCC(connect(sk, (struct sockaddr *)&peer_addr_a,
			  sizeof(peer_addr_a)));

	TEST_SUCC(connect(sk, &unspec_addr, UNSPEC_LEN));
	CHECK_NO_PEER(sk);

	// The address specified by `bind` is kept, but the port is released.
	CHECK_SOCKNAME(sk, loopback_addr.sin_addr.s_addr, 0);

	// Sending binds the socket to a new port at the kept address.
	SEND(sk, "s", peer_addr_b);
	TEST_RES(getsockname(sk, (struct sockaddr *)&name, &namelen),
		 name.sin_addr.s_addr == loopback_addr.sin_addr.s_addr &&
			 name.sin_port != 0);
	RECV_FROM(peer_b, name.sin_port, 's');

	CHECK_NO_DEST(sk);
	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(udp_sendto_unspec)
{
	struct sockaddr_in to = peer_addr_a;
	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	struct iovec iov = { .iov_base = "m", .iov_len = 1 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
	int sk;

	sk = new_udp_socket();

	// An `AF_UNSPEC` destination is used as an `AF_INET` one.
	to.sin_family = AF_UNSPEC;
	SEND(sk, "u", to);
	TEST_SUCC(getsockname(sk, (struct sockaddr *)&name, &namelen));
	RECV_FROM(peer_a, name.sin_port, 'u');

	TEST_ERRNO(sendto(sk, "u", 1, 0, &unspec_addr, UNSPEC_LEN), EINVAL);
	TEST_ERRNO(sendto(sk, "u", 1, 0, (struct sockaddr *)&unspec_inet,
			  sizeof(unspec_inet)),
		   EINVAL);

	// A zero name length means no destination.
	TEST_SUCC(connect(sk, (struct sockaddr *)&peer_addr_b,
			  sizeof(peer_addr_b)));
	msg.msg_name = &to;
	msg.msg_namelen = 0;
	TEST_RES(sendmsg(sk, &msg, 0), _ret == 1);
	RECV_FROM(peer_b, name.sin_port, 'm');

	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(inet_bind_unspec)
{
	struct sockaddr_in addr = unspec_inet;
	struct sockaddr_in6 addr6 = { .sin6_family = AF_UNSPEC };
	int sk;

	// IPv4 sockets bind to `AF_UNSPEC` addresses only if they are `INADDR_ANY`.
	sk = new_udp_socket();
	TEST_ERRNO(bind(sk, &unspec_addr, UNSPEC_LEN), EINVAL);
	addr.sin_addr = loopback_addr.sin_addr;
	TEST_ERRNO(bind(sk, (struct sockaddr *)&addr, sizeof(addr)),
		   EAFNOSUPPORT);
	TEST_SUCC(close(sk));

	sk = CHECK(socket(PF_INET, SOCK_STREAM, 0));
	TEST_ERRNO(bind(sk, (struct sockaddr *)&addr, sizeof(addr)),
		   EAFNOSUPPORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = BOUND_PORT;
	TEST_SUCC(bind(sk, (struct sockaddr *)&addr, sizeof(addr)));
	CHECK_SOCKNAME(sk, htonl(INADDR_ANY), BOUND_PORT);
	TEST_SUCC(close(sk));

	sk = CHECK(socket(PF_INET6, SOCK_STREAM, 0));
	TEST_ERRNO(bind(sk, (struct sockaddr *)&addr6, sizeof(addr6)),
		   EAFNOSUPPORT);
	TEST_SUCC(close(sk));
}
END_TEST()

// FIXME: Asterinas does not support binding UDP sockets to `INADDR_ANY` yet.
#ifndef __asterinas__
FN_TEST(udp_bind_unspec_any_addr)
{
	struct sockaddr_in addr = unspec_inet;
	int sk;

	sk = new_udp_socket();
	addr.sin_port = BOUND_PORT;
	TEST_SUCC(bind(sk, (struct sockaddr *)&addr, sizeof(addr)));
	CHECK_SOCKNAME(sk, htonl(INADDR_ANY), BOUND_PORT);
	TEST_SUCC(close(sk));
}
END_TEST()
#endif

FN_TEST(tcp_disconnect_unconnected)
{
	struct sockaddr_in addr = loopback_addr;
	socklen_t addrlen = sizeof(addr);
	int listener, sk;

	listener = CHECK(socket(PF_INET, SOCK_STREAM, 0));
	CHECK(bind(listener, (struct sockaddr *)&addr, sizeof(addr)));
	CHECK(getsockname(listener, (struct sockaddr *)&addr, &addrlen));
	CHECK(listen(listener, 1));

	sk = CHECK(socket(PF_INET, SOCK_STREAM, 0));
	TEST_ERRNO(connect(sk, &unspec_addr, 1), EINVAL);
	TEST_SUCC(connect(sk, &unspec_addr, UNSPEC_LEN));

	// The socket can still connect.
	TEST_SUCC(connect(sk, (struct sockaddr *)&addr, sizeof(addr)));

	TEST_SUCC(close(sk));
	TEST_SUCC(close(listener));
}
END_TEST()

static int new_abstract_unix_dgram(const char *name, struct sockaddr_un *addr,
				   socklen_t *addrlen)
{
	int sk;

	addr->sun_family = AF_UNIX;
	addr->sun_path[0] = '\0';
	strcpy(addr->sun_path + 1, name);
	*addrlen = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name);

	sk = CHECK(socket(AF_UNIX, SOCK_DGRAM, 0));
	CHECK(bind(sk, (struct sockaddr *)addr, *addrlen));

	return sk;
}

FN_TEST(unix_dgram_disconnect)
{
	struct sockaddr_un addr_a, addr_b, peer;
	socklen_t addrlen_a, addrlen_b, peerlen = sizeof(peer);
	char buf[2];
	int sk_a, sk_b;

	sk_a = new_abstract_unix_dgram("af_unspec_a", &addr_a, &addrlen_a);
	sk_b = new_abstract_unix_dgram("af_unspec_b", &addr_b, &addrlen_b);
	TEST_SUCC(connect(sk_a, (struct sockaddr *)&addr_b, addrlen_b));

	// Disconnecting drops the received messages.
	TEST_RES(sendto(sk_b, "a", 1, 0, (struct sockaddr *)&addr_a, addrlen_a),
		 _ret == 1);
	TEST_SUCC(connect(sk_a, &unspec_addr, UNSPEC_LEN));
	TEST_ERRNO(recv(sk_a, buf, sizeof(buf), MSG_DONTWAIT), EAGAIN);

	TEST_ERRNO(getpeername(sk_a, (struct sockaddr *)&peer, &peerlen),
		   ENOTCONN);
	TEST_ERRNO(send(sk_a, "b", 1, 0), ENOTCONN);

	// Messages are received again.
	TEST_RES(sendto(sk_b, "c", 1, 0, (struct sockaddr *)&addr_a, addrlen_a),
		 _ret == 1);
	TEST_RES(recv(sk_a, buf, sizeof(buf), MSG_DONTWAIT),
		 _ret == 1 && buf[0] == 'c');

	TEST_SUCC(connect(sk_a, &unspec_addr, UNSPEC_LEN));

	TEST_ERRNO(connect(sk_a, &unspec_addr, 1), EINVAL);
	TEST_ERRNO(bind(sk_a, &unspec_addr, UNSPEC_LEN), EINVAL);
	TEST_ERRNO(sendto(sk_a, "d", 1, 0, &unspec_addr, UNSPEC_LEN), EINVAL);

	TEST_SUCC(close(sk_a));
	TEST_SUCC(close(sk_b));
}
END_TEST()

FN_TEST(unix_dgram_peer_only)
{
	struct sockaddr_un addr_a, addr_b, addr_c;
	socklen_t addrlen_a, addrlen_b, addrlen_c;
	char buf[2];
	int sk_a, sk_b, sk_c;

	sk_a = new_abstract_unix_dgram("af_unspec_pa", &addr_a, &addrlen_a);
	sk_b = new_abstract_unix_dgram("af_unspec_pb", &addr_b, &addrlen_b);
	sk_c = new_abstract_unix_dgram("af_unspec_pc", &addr_c, &addrlen_c);
	TEST_SUCC(connect(sk_a, (struct sockaddr *)&addr_b, addrlen_b));

	// A connected socket only accepts messages and connections from its peer.
	TEST_ERRNO(sendto(sk_c, "a", 1, 0, (struct sockaddr *)&addr_a, addrlen_a),
		   EPERM);
	TEST_ERRNO(connect(sk_c, (struct sockaddr *)&addr_a, addrlen_a), EPERM);
	TEST_RES(sendto(sk_b, "b", 1, 0, (struct sockaddr *)&addr_a, addrlen_a),
		 _ret == 1);
	TEST_RES(recv(sk_a, buf, sizeof(buf), MSG_DONTWAIT),
		 _ret == 1 && buf[0] == 'b');

	// After disconnecting, it accepts messages from others again.
	TEST_SUCC(connect(sk_a, &unspec_addr, UNSPEC_LEN));
	TEST_RES(sendto(sk_c, "c", 1, 0, (struct sockaddr *)&addr_a, addrlen_a),
		 _ret == 1);
	TEST_RES(recv(sk_a, buf, sizeof(buf), MSG_DONTWAIT),
		 _ret == 1 && buf[0] == 'c');

	TEST_SUCC(close(sk_a));
	TEST_SUCC(close(sk_b));
	TEST_SUCC(close(sk_c));
}
END_TEST()

FN_TEST(unix_stream_unspec)
{
	int sk;

	sk = CHECK(socket(AF_UNIX, SOCK_STREAM, 0));
	TEST_ERRNO(connect(sk, &unspec_addr, UNSPEC_LEN), EINVAL);
	TEST_ERRNO(bind(sk, &unspec_addr, UNSPEC_LEN), EINVAL);
	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(netlink_unspec)
{
	struct sockaddr_nl addr;
	socklen_t addrlen = sizeof(addr);
	struct sockaddr_nl unspec_nl = { .nl_family = AF_UNSPEC };
	int sk;

	sk = CHECK(socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));

	// Disconnecting does not bind the socket.
	TEST_ERRNO(connect(sk, &unspec_addr, 1), EINVAL);
	TEST_SUCC(connect(sk, &unspec_addr, UNSPEC_LEN));
	TEST_RES(getsockname(sk, (struct sockaddr *)&addr, &addrlen),
		 addr.nl_family == AF_NETLINK && addr.nl_pid == 0);

	TEST_ERRNO(bind(sk, (struct sockaddr *)&unspec_nl, sizeof(unspec_nl)),
		   EINVAL);
	TEST_ERRNO(sendto(sk, "n", 1, 0, (struct sockaddr *)&unspec_nl,
			  sizeof(unspec_nl)),
		   EINVAL);

	TEST_SUCC(close(sk));
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(close(peer_a));
	CHECK(close(peer_b));
}
END_SETUP()
