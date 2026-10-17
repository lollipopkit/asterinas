// SPDX-License-Identifier: MPL-2.0

#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../common/test.h"

static int new_bound_socket(struct sockaddr_in *addr, int reuse)
{
	int sk;
	socklen_t addrlen = sizeof(*addr);

	sk = CHECK(socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	CHECK(setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)));
	CHECK(bind(sk, (struct sockaddr *)addr, sizeof(*addr)));
	CHECK(getsockname(sk, (struct sockaddr *)addr, &addrlen));

	return sk;
}

static struct sockaddr_in addr_a, addr_b, addr_c, addr_d;
static int sk_a, sk_b, sk_c, sk_d;

FN_SETUP(sockets)
{
	addr_a.sin_family = AF_INET;
	CHECK(inet_aton("127.0.0.1", &addr_a.sin_addr));
	addr_b = addr_c = addr_d = addr_a;

	sk_a = new_bound_socket(&addr_a, 0);
	sk_b = new_bound_socket(&addr_b, 0);
	sk_c = new_bound_socket(&addr_c, 0);
	sk_d = new_bound_socket(&addr_d, 0);
}
END_SETUP()

#define SEND(sk, buf, to)                                                     \
	TEST_RES(sendto(sk, buf, 1, 0, (struct sockaddr *)&to, sizeof(to)), \
		 _ret == 1)

// Waits for a datagram, since the loopback delivery can be asynchronous.
#define WAIT_READABLE(sk)                                                 \
	do {                                                              \
		struct pollfd __pfd = { .fd = sk, .events = POLLIN };     \
		TEST_RES(poll(&__pfd, 1, 1000), _ret == 1);               \
	} while (0)

#define RECV_FROM(sk, from, expected)                                          \
	do {                                                                   \
		char __buf[2];                                                 \
		struct sockaddr_in __from;                                     \
		socklen_t __fromlen = sizeof(__from);                          \
		WAIT_READABLE(sk);                                             \
		TEST_RES(recvfrom(sk, __buf, sizeof(__buf), 0,                 \
				  (struct sockaddr *)&__from, &__fromlen),     \
			 _ret == 1 && __buf[0] == expected &&                  \
				 __from.sin_port == from.sin_port);            \
	} while (0)

#define RECV_NONE(sk)                                    \
	do {                                             \
		char __buf[2];                           \
		TEST_ERRNO(recv(sk, __buf, sizeof(__buf), 0), \
			   EAGAIN);                      \
	} while (0)

// Datagrams that should be dropped are sent before the ones that should be received, so the
// former must have been processed when the latter arrive.

FN_TEST(queued_before_connect)
{
	// Datagrams received before connecting are kept.
	SEND(sk_c, "c", addr_d);
	WAIT_READABLE(sk_d);
	TEST_SUCC(connect(sk_d, (struct sockaddr *)&addr_b, sizeof(addr_b)));

	SEND(sk_c, "C", addr_d);
	SEND(sk_b, "b", addr_d);
	RECV_FROM(sk_d, addr_c, 'c');
	RECV_FROM(sk_d, addr_b, 'b');
	RECV_NONE(sk_d);
}
END_TEST()

FN_TEST(connected_peer_only)
{
	TEST_SUCC(connect(sk_a, (struct sockaddr *)&addr_b, sizeof(addr_b)));

	SEND(sk_c, "c", addr_a);
	SEND(sk_b, "b", addr_a);
	RECV_FROM(sk_a, addr_b, 'b');
	RECV_NONE(sk_a);

	// After reconnecting, only datagrams from the new peer are received.
	TEST_SUCC(connect(sk_a, (struct sockaddr *)&addr_c, sizeof(addr_c)));

	SEND(sk_b, "b", addr_a);
	SEND(sk_c, "c", addr_a);
	RECV_FROM(sk_a, addr_c, 'c');
	RECV_NONE(sk_a);
}
END_TEST()

FN_TEST(prefer_connected)
{
	struct sockaddr_in addr_e;
	int sk_e1, sk_e2;

	// Bind two sockets to the same address, then connect the first one to B.
	addr_e = addr_a;
	addr_e.sin_port = 0;
	sk_e1 = new_bound_socket(&addr_e, 1);
	sk_e2 = new_bound_socket(&addr_e, 1);
	TEST_SUCC(connect(sk_e1, (struct sockaddr *)&addr_b, sizeof(addr_b)));

	// Datagrams from B go to the connected socket, while datagrams from others go to the
	// unconnected socket.
	SEND(sk_c, "c", addr_e);
	SEND(sk_b, "b", addr_e);
	RECV_FROM(sk_e1, addr_b, 'b');
	RECV_FROM(sk_e2, addr_c, 'c');
	RECV_NONE(sk_e1);
	RECV_NONE(sk_e2);

	TEST_SUCC(close(sk_e1));
	TEST_SUCC(close(sk_e2));
}
END_TEST()

FN_SETUP(cleanup)
{
	CHECK(close(sk_a));
	CHECK(close(sk_b));
	CHECK(close(sk_c));
	CHECK(close(sk_d));
}
END_SETUP()
