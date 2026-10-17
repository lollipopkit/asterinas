// SPDX-License-Identifier: MPL-2.0

#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../common/test.h"

static const struct sockaddr unspec_addr = { .sa_family = AF_UNSPEC };
static struct sockaddr_in any_addr, loopback_addr, broadcast_addr;
// The address of a non-loopback iface, or `INADDR_ANY` if there is no such iface.
static struct sockaddr_in iface_addr;

static int new_udp_socket(int reuse)
{
	int sk;

	sk = CHECK(socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
	CHECK(setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)));

	return sk;
}

static int new_bound_udp_socket(struct sockaddr_in *addr, int reuse)
{
	int sk;
	socklen_t addrlen = sizeof(*addr);

	sk = new_udp_socket(reuse);
	CHECK(bind(sk, (struct sockaddr *)addr, sizeof(*addr)));
	CHECK(getsockname(sk, (struct sockaddr *)addr, &addrlen));

	return sk;
}

#define BOUND_PORT htons(0x3456)

static struct sockaddr_in with_port(struct sockaddr_in addr, in_port_t port)
{
	addr.sin_port = port;
	return addr;
}

FN_SETUP(addrs)
{
	struct sockaddr_in remote = { .sin_family = AF_INET,
				      .sin_port = htons(53) };
	socklen_t addrlen = sizeof(iface_addr);
	int sk;

	any_addr.sin_family = AF_INET;
	any_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	loopback_addr.sin_family = AF_INET;
	CHECK(inet_aton("127.0.0.1", &loopback_addr.sin_addr));

	broadcast_addr.sin_family = AF_INET;
	CHECK(inet_aton("127.255.255.255", &broadcast_addr.sin_addr));

	// Connecting a UDP socket sends nothing but selects the source address by routing.
	iface_addr = any_addr;
	CHECK(inet_aton("8.8.8.8", &remote.sin_addr));
	sk = new_udp_socket(0);
	if (connect(sk, (struct sockaddr *)&remote, sizeof(remote)) == 0)
		CHECK(getsockname(sk, (struct sockaddr *)&iface_addr,
				  &addrlen));
	iface_addr.sin_port = 0;
	CHECK(close(sk));
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

#define RECV_FROM(sk, from, expected)                                         \
	do {                                                                  \
		char __buf[2];                                                \
		struct sockaddr_in __from;                                    \
		socklen_t __fromlen = sizeof(__from);                         \
		WAIT_READABLE(sk);                                            \
		TEST_RES(recvfrom(sk, __buf, sizeof(__buf), 0,                \
				  (struct sockaddr *)&__from, &__fromlen),    \
			 _ret == 1 && __buf[0] == expected &&                 \
				 __from.sin_addr.s_addr ==                    \
					 (from).sin_addr.s_addr &&            \
				 __from.sin_port == (from).sin_port);         \
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

FN_TEST(bind_any)
{
	struct sockaddr_in addr = any_addr;
	int sk, sk2;

	// An ephemeral port is the same on all ifaces.
	sk = new_bound_udp_socket(&addr, 0);
	TEST_RES(addr.sin_port, _ret != 0);
	CHECK_SOCKNAME(sk, htonl(INADDR_ANY), addr.sin_port);

	// The port is in use at all addresses.
	sk2 = new_udp_socket(0);
	TEST_ERRNO(bind(sk2, (struct sockaddr *)&addr, sizeof(addr)),
		   EADDRINUSE);
	addr.sin_addr = loopback_addr.sin_addr;
	TEST_ERRNO(bind(sk2, (struct sockaddr *)&addr, sizeof(addr)),
		   EADDRINUSE);
	TEST_SUCC(close(sk));

	// A specified port can be bound again after the socket is closed.
	addr.sin_addr = any_addr.sin_addr;
	TEST_SUCC(bind(sk2, (struct sockaddr *)&addr, sizeof(addr)));
	CHECK_SOCKNAME(sk2, htonl(INADDR_ANY), addr.sin_port);

	// The socket is already bound.
	TEST_ERRNO(bind(sk2, (struct sockaddr *)&addr, sizeof(addr)), EINVAL);
	TEST_SUCC(close(sk2));
}
END_TEST()

FN_TEST(bind_any_conflicts)
{
	struct sockaddr_in addr = loopback_addr;
	int sk, sk2;

	// A specified address conflicts with the unspecified address.
	sk = new_bound_udp_socket(&addr, 0);
	sk2 = new_udp_socket(0);
	addr.sin_addr = any_addr.sin_addr;
	TEST_ERRNO(bind(sk2, (struct sockaddr *)&addr, sizeof(addr)),
		   EADDRINUSE);
	TEST_SUCC(close(sk2));

	// Enabling `SO_REUSEADDR` on only one of the sockets is not enough.
	sk2 = new_udp_socket(1);
	TEST_ERRNO(bind(sk2, (struct sockaddr *)&addr, sizeof(addr)),
		   EADDRINUSE);
	TEST_SUCC(close(sk2));
	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(recv_any)
{
	struct sockaddr_in addr = any_addr;
	struct sockaddr_in sender_addr = loopback_addr;
	struct sockaddr_in to;
	int sk, sender;

	sk = new_bound_udp_socket(&addr, 0);
	sender = new_bound_udp_socket(&sender_addr, 0);

	// Datagrams to the loopback address are received.
	to = with_port(loopback_addr, addr.sin_port);
	SEND(sender, "a", to);
	RECV_FROM(sk, sender_addr, 'a');

	// The source address is selected for each datagram by routing.
	SEND(sk, "b", sender_addr);
	RECV_FROM(sender, to, 'b');

	TEST_SUCC(close(sender));
	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(recv_any_iface)
{
	struct sockaddr_in addr = any_addr;
	struct sockaddr_in sender_addr = iface_addr;
	struct sockaddr_in to;
	int sk, sender;

	SKIP_TEST_IF(iface_addr.sin_addr.s_addr == htonl(INADDR_ANY));

	sk = new_bound_udp_socket(&addr, 0);
	sender = new_bound_udp_socket(&sender_addr, 0);

	// Datagrams to the address of another iface are also received.
	to = with_port(iface_addr, addr.sin_port);
	SEND(sender, "a", to);
	RECV_FROM(sk, sender_addr, 'a');

	// The source address is selected for each datagram by routing.
	SEND(sk, "b", sender_addr);
	RECV_FROM(sender, to, 'b');

	TEST_SUCC(close(sender));
	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(recv_specific_over_any)
{
	struct sockaddr_in addr = with_port(any_addr, BOUND_PORT);
	struct sockaddr_in specific_addr, to_broadcast;
	struct sockaddr_in sender_addr = loopback_addr;
	int sk_any, sk_specific, sender;
	int one = 1;

	sk_any = new_bound_udp_socket(&addr, 1);
	specific_addr = with_port(loopback_addr, addr.sin_port);
	sk_specific = new_bound_udp_socket(&specific_addr, 1);
	sender = new_bound_udp_socket(&sender_addr, 0);

	// The socket bound at the destination address is preferred.
	SEND(sender, "a", specific_addr);
	RECV_FROM(sk_specific, sender_addr, 'a');
	RECV_NONE(sk_any);

	// Broadcast datagrams are only received by the socket bound at the
	// unspecified address.
	CHECK(setsockopt(sender, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)));
	to_broadcast = with_port(broadcast_addr, addr.sin_port);
	SEND(sender, "b", to_broadcast);
	RECV_FROM(sk_any, sender_addr, 'b');
	RECV_NONE(sk_specific);

	// Connecting binds the socket at the source address, and a connected
	// socket is preferred over an unconnected one.
	TEST_SUCC(connect(sk_any, (struct sockaddr *)&sender_addr,
			  sizeof(sender_addr)));
	CHECK_SOCKNAME(sk_any, loopback_addr.sin_addr.s_addr, addr.sin_port);
	SEND(sender, "c", specific_addr);
	RECV_FROM(sk_any, sender_addr, 'c');
	RECV_NONE(sk_specific);

	// Disconnecting binds the socket at the unspecified address again, and
	// the port is kept since it is specified by `bind`.
	TEST_SUCC(connect(sk_any, &unspec_addr, sizeof(sa_family_t)));
	CHECK_SOCKNAME(sk_any, htonl(INADDR_ANY), addr.sin_port);
	SEND(sender, "d", specific_addr);
	RECV_FROM(sk_specific, sender_addr, 'd');
	RECV_NONE(sk_any);

	// The socket bound at the unspecified address receives the datagrams
	// after the other socket is closed.
	TEST_SUCC(close(sk_specific));
	SEND(sender, "e", specific_addr);
	RECV_FROM(sk_any, sender_addr, 'e');
	RECV_NONE(sk_any);

	TEST_SUCC(close(sender));
	TEST_SUCC(close(sk_any));
}
END_TEST()

FN_TEST(connect_any)
{
	struct sockaddr_in addr = any_addr;
	struct sockaddr_in peer_addr = loopback_addr;
	struct sockaddr_in other_addr = loopback_addr;
	struct sockaddr_in local_addr;
	int sk, peer, other;

	sk = new_bound_udp_socket(&addr, 0);
	peer = new_bound_udp_socket(&peer_addr, 0);
	other = new_bound_udp_socket(&other_addr, 0);
	local_addr = with_port(loopback_addr, addr.sin_port);

	// Connecting selects the local address by routing.
	TEST_SUCC(connect(sk, (struct sockaddr *)&peer_addr,
			  sizeof(peer_addr)));
	CHECK_SOCKNAME(sk, loopback_addr.sin_addr.s_addr, addr.sin_port);

	TEST_RES(send(sk, "a", 1, 0), _ret == 1);
	RECV_FROM(peer, local_addr, 'a');
	SEND(peer, "b", local_addr);
	RECV_FROM(sk, peer_addr, 'b');

	// The local address is kept when connecting again.
	TEST_SUCC(connect(sk, (struct sockaddr *)&other_addr,
			  sizeof(other_addr)));
	CHECK_SOCKNAME(sk, loopback_addr.sin_addr.s_addr, addr.sin_port);
	TEST_RES(send(sk, "c", 1, 0), _ret == 1);
	RECV_FROM(other, local_addr, 'c');

	// Disconnecting releases the port since it is not specified by `bind`.
	TEST_SUCC(connect(sk, &unspec_addr, sizeof(sa_family_t)));
	CHECK_SOCKNAME(sk, htonl(INADDR_ANY), 0);

	TEST_SUCC(close(other));
	TEST_SUCC(close(peer));
	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(auto_bind_any)
{
	struct sockaddr_in name, local_addr;
	socklen_t namelen = sizeof(name);
	struct sockaddr_in peer_addr = loopback_addr;
	int sk, peer;

	peer = new_bound_udp_socket(&peer_addr, 0);

	// Sending binds an unbound socket at the unspecified address.
	sk = new_udp_socket(0);
	SEND(sk, "a", peer_addr);
	TEST_RES(getsockname(sk, (struct sockaddr *)&name, &namelen),
		 name.sin_addr.s_addr == htonl(INADDR_ANY) &&
			 name.sin_port != 0);
	local_addr = with_port(loopback_addr, name.sin_port);
	RECV_FROM(peer, local_addr, 'a');

	SEND(peer, "b", local_addr);
	RECV_FROM(sk, peer_addr, 'b');

	TEST_SUCC(close(sk));
	TEST_SUCC(close(peer));
}
END_TEST()
