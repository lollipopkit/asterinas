// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>

#include "../common/test.h"

// `MSG_DONTWAIT` makes a single operation non-blocking, even if the socket
// is blocking. All the sockets in this test are blocking.

static char buf[4096];

static void tcp_pair(int *client, int *server)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t addrlen = sizeof(addr);
	int listener = CHECK(socket(AF_INET, SOCK_STREAM, 0));

	CHECK(bind(listener, (struct sockaddr *)&addr, sizeof(addr)));
	CHECK(listen(listener, 1));
	CHECK(getsockname(listener, (struct sockaddr *)&addr, &addrlen));

	*client = CHECK(socket(AF_INET, SOCK_STREAM, 0));
	CHECK(connect(*client, (struct sockaddr *)&addr, sizeof(addr)));
	*server = CHECK(accept(listener, NULL, NULL));
	CHECK(close(listener));
}

// Sends until the send buffer is full, which must not block.
#define TEST_SEND_UNTIL_FULL(fd)                                              \
	do {                                                                  \
		ssize_t sent;                                                 \
		do {                                                          \
			sent = send(fd, buf, sizeof(buf), MSG_DONTWAIT);      \
		} while (sent > 0);                                           \
		TEST_ERRNO(send(fd, buf, sizeof(buf), MSG_DONTWAIT), EAGAIN); \
	} while (0)

FN_TEST(tcp)
{
	int client, server;

	tcp_pair(&client, &server);

	TEST_ERRNO(recv(server, buf, sizeof(buf), MSG_DONTWAIT), EAGAIN);
	TEST_SEND_UNTIL_FULL(client);

	TEST_SUCC(close(server));
	TEST_SUCC(close(client));
}
END_TEST()

FN_TEST(udp)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int sk = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));

	TEST_SUCC(bind(sk, (struct sockaddr *)&addr, sizeof(addr)));
	TEST_ERRNO(recv(sk, buf, sizeof(buf), MSG_DONTWAIT), EAGAIN);

	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(unix_stream)
{
	int fds[2];

	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

	TEST_ERRNO(recv(fds[0], buf, sizeof(buf), MSG_DONTWAIT), EAGAIN);
	TEST_SEND_UNTIL_FULL(fds[1]);

	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()

FN_TEST(unix_datagram)
{
	int fds[2];

	TEST_SUCC(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds));
	TEST_ERRNO(recv(fds[0], buf, sizeof(buf), MSG_DONTWAIT), EAGAIN);
	TEST_SEND_UNTIL_FULL(fds[1]);

	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()

FN_TEST(netlink)
{
	int sk = TEST_SUCC(socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));

	TEST_ERRNO(recv(sk, buf, sizeof(buf), MSG_DONTWAIT), EAGAIN);

	TEST_SUCC(close(sk));
}
END_TEST()
