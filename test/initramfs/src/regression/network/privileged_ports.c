// SPDX-License-Identifier: MPL-2.0

#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "../common/test.h"

static struct sockaddr_in sk_addr;

FN_SETUP(init)
{
	// This does not always work, but it is the most simple way
	// to drop the `CAP_NET_BIND_SERVICE` capability in common cases.
	if (getuid() == 0)
		CHECK(setuid(65534));

	sk_addr.sin_family = AF_INET;
	CHECK(inet_aton("127.0.0.1", &sk_addr.sin_addr));
}
END_SETUP()

FN_TEST(tcp_privileged_ports)
{
	int sk;

	sk = TEST_SUCC(socket(PF_INET, SOCK_STREAM, 0));

	sk_addr.sin_port = htons(1023);
	TEST_ERRNO(bind(sk, (struct sockaddr *)&sk_addr, sizeof(sk_addr)),
		   EACCES);

	sk_addr.sin_port = htons(1024);
	TEST_SUCC(bind(sk, (struct sockaddr *)&sk_addr, sizeof(sk_addr)));

	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(udp_privileged_ports)
{
	int sk;

	sk = TEST_SUCC(socket(PF_INET, SOCK_DGRAM, 0));

	sk_addr.sin_port = htons(1023);
	TEST_ERRNO(bind(sk, (struct sockaddr *)&sk_addr, sizeof(sk_addr)),
		   EACCES);

	sk_addr.sin_port = htons(1024);
	TEST_SUCC(bind(sk, (struct sockaddr *)&sk_addr, sizeof(sk_addr)));

	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(ephemeral_ports)
{
	int sk, listener;
	socklen_t len = sizeof(sk_addr);

	// Port 0 picks an ephemeral port, which needs no privilege.
	sk = TEST_SUCC(socket(PF_INET, SOCK_DGRAM, 0));
	sk_addr.sin_port = htons(0);
	TEST_SUCC(bind(sk, (struct sockaddr *)&sk_addr, sizeof(sk_addr)));
	TEST_RES(getsockname(sk, (struct sockaddr *)&sk_addr, &len),
		 ntohs(sk_addr.sin_port) >= 1024);
	TEST_SUCC(close(sk));

	// So does an implicit bind on `connect` or `sendto`.
	sk = TEST_SUCC(socket(PF_INET, SOCK_DGRAM, 0));
	sk_addr.sin_port = htons(2000);
	TEST_SUCC(connect(sk, (struct sockaddr *)&sk_addr, sizeof(sk_addr)));
	TEST_SUCC(close(sk));

	sk = TEST_SUCC(socket(PF_INET, SOCK_DGRAM, 0));
	TEST_RES(sendto(sk, "x", 1, 0, (struct sockaddr *)&sk_addr,
			sizeof(sk_addr)),
		 _ret == 1);
	TEST_SUCC(close(sk));

	listener = TEST_SUCC(socket(PF_INET, SOCK_STREAM, 0));
	sk_addr.sin_port = htons(0);
	TEST_SUCC(bind(listener, (struct sockaddr *)&sk_addr, sizeof(sk_addr)));
	TEST_SUCC(listen(listener, 1));
	len = sizeof(sk_addr);
	TEST_SUCC(getsockname(listener, (struct sockaddr *)&sk_addr, &len));
	sk = TEST_SUCC(socket(PF_INET, SOCK_STREAM, 0));
	TEST_SUCC(connect(sk, (struct sockaddr *)&sk_addr, sizeof(sk_addr)));
	TEST_SUCC(close(sk));
	TEST_SUCC(close(listener));
}
END_TEST()
