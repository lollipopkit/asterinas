// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../common/test.h"

static int bound_port(int sk)
{
	struct sockaddr_in6 addr;
	socklen_t addrlen = sizeof(addr);

	CHECK(getsockname(sk, (struct sockaddr *)&addr, &addrlen));
	return ntohs(addr.sin6_port);
}

static int listen_ipv4_any(int port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};
	int sk = CHECK(socket(AF_INET, SOCK_STREAM, 0));

	CHECK(bind(sk, (struct sockaddr *)&addr, sizeof(addr)));
	CHECK(listen(sk, 2));
	return sk;
}

static int connect_ipv4_loopback(int port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int sk = CHECK(socket(AF_INET, SOCK_STREAM, 0));

	CHECK(connect(sk, (struct sockaddr *)&addr, sizeof(addr)));
	return sk;
}

static int connect_ipv6_loopback(int port)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	int sk = CHECK(socket(AF_INET6, SOCK_STREAM, 0));

	CHECK(connect(sk, (struct sockaddr *)&addr, sizeof(addr)));
	return sk;
}

static int is_ipv4_mapped_loopback(const struct in6_addr *addr)
{
	struct in6_addr expected;

	CHECK(inet_pton(AF_INET6, "::ffff:127.0.0.1", &expected));
	return memcmp(addr, &expected, sizeof(expected)) == 0;
}

FN_TEST(ipv4_any_listen)
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	int sk_listen, sk_connect, sk_accept, port;
	char buf = 'a';

	sk_listen = listen_ipv4_any(0);
	TEST_RES(getsockname(sk_listen, (struct sockaddr *)&addr, &addrlen),
		 addrlen == sizeof(addr) &&
			 addr.sin_addr.s_addr == htonl(INADDR_ANY) &&
			 addr.sin_port != 0);
	port = ntohs(addr.sin_port);

	sk_connect = connect_ipv4_loopback(port);

	addrlen = sizeof(addr);
	sk_accept = TEST_RES(
		accept(sk_listen, (struct sockaddr *)&addr, &addrlen),
		addrlen == sizeof(addr) &&
			addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
			addr.sin_port == htons(bound_port(sk_connect)));

	addrlen = sizeof(addr);
	TEST_RES(getsockname(sk_accept, (struct sockaddr *)&addr, &addrlen),
		 addrlen == sizeof(addr) &&
			 addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
			 addr.sin_port == htons(port));

	TEST_RES(write(sk_connect, &buf, 1), _ret == 1);
	buf = 0;
	TEST_RES(read(sk_accept, &buf, 1), _ret == 1 && buf == 'a');

	TEST_SUCC(close(sk_accept));
	TEST_SUCC(close(sk_connect));
	TEST_SUCC(close(sk_listen));
}
END_TEST()

FN_TEST(listen_without_bind)
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	int sk_listen, sk_connect, sk_accept;

	sk_listen = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SUCC(listen(sk_listen, 2));
	TEST_RES(getsockname(sk_listen, (struct sockaddr *)&addr, &addrlen),
		 addrlen == sizeof(addr) &&
			 addr.sin_addr.s_addr == htonl(INADDR_ANY) &&
			 addr.sin_port != 0);

	sk_connect = connect_ipv4_loopback(ntohs(addr.sin_port));
	sk_accept = TEST_SUCC(accept(sk_listen, NULL, NULL));

	TEST_SUCC(close(sk_accept));
	TEST_SUCC(close(sk_connect));
	TEST_SUCC(close(sk_listen));
}
END_TEST()

FN_TEST(any_conflicts_with_specified)
{
	struct sockaddr_in any = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};
	struct sockaddr_in loopback = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int sk1, sk2, enable = 1;

	// Binding a specified address conflicts with the unspecified address.
	sk1 = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SUCC(bind(sk1, (struct sockaddr *)&any, sizeof(any)));
	loopback.sin_port = htons(bound_port(sk1));
	sk2 = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_ERRNO(bind(sk2, (struct sockaddr *)&loopback, sizeof(loopback)),
		   EADDRINUSE);
	TEST_SUCC(close(sk2));
	TEST_SUCC(close(sk1));

	// Binding the unspecified address conflicts with a specified address.
	loopback.sin_port = 0;
	sk1 = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SUCC(bind(sk1, (struct sockaddr *)&loopback, sizeof(loopback)));
	any.sin_port = htons(bound_port(sk1));
	sk2 = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_ERRNO(bind(sk2, (struct sockaddr *)&any, sizeof(any)), EADDRINUSE);

	// The conflict goes away if both sockets enable `SO_REUSEADDR`.
	TEST_SUCC(setsockopt(sk1, SOL_SOCKET, SO_REUSEADDR, &enable,
			     sizeof(enable)));
	TEST_SUCC(setsockopt(sk2, SOL_SOCKET, SO_REUSEADDR, &enable,
			     sizeof(enable)));
	TEST_SUCC(bind(sk2, (struct sockaddr *)&any, sizeof(any)));

	TEST_SUCC(close(sk2));
	TEST_SUCC(close(sk1));
}
END_TEST()

FN_TEST(connect_after_binding_any)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};
	socklen_t addrlen = sizeof(addr);
	int sk_listen, sk_connect, sk_accept, port;

	sk_listen = listen_ipv4_any(0);

	sk_connect = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SUCC(bind(sk_connect, (struct sockaddr *)&addr, sizeof(addr)));
	port = bound_port(sk_connect);

	addr.sin_port = htons(bound_port(sk_listen));
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	TEST_SUCC(connect(sk_connect, (struct sockaddr *)&addr, sizeof(addr)));

	// The port is kept, and the address is chosen by routing.
	TEST_RES(getsockname(sk_connect, (struct sockaddr *)&addr, &addrlen),
		 addrlen == sizeof(addr) &&
			 addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
			 addr.sin_port == htons(port));

	sk_accept = TEST_SUCC(accept(sk_listen, NULL, NULL));

	TEST_SUCC(close(sk_accept));
	TEST_SUCC(close(sk_connect));
	TEST_SUCC(close(sk_listen));
}
END_TEST()

FN_TEST(ipv6_dual_stack)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT,
	};
	socklen_t addrlen = sizeof(addr);
	int sk_listen, sk_connect, sk_accept, port, v6only = -1;
	socklen_t optlen = sizeof(v6only);

	sk_listen = TEST_SUCC(socket(AF_INET6, SOCK_STREAM, 0));
	TEST_RES(getsockopt(sk_listen, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
			    &optlen),
		 optlen == sizeof(v6only) && v6only == 0);
	TEST_SUCC(bind(sk_listen, (struct sockaddr *)&addr, sizeof(addr)));
	TEST_SUCC(listen(sk_listen, 2));
	port = bound_port(sk_listen);

	// An IPv4 connection is accepted with an IPv4-mapped IPv6 address.
	sk_connect = connect_ipv4_loopback(port);
	sk_accept = TEST_RES(
		accept(sk_listen, (struct sockaddr *)&addr, &addrlen),
		addrlen == sizeof(addr) && addr.sin6_family == AF_INET6 &&
			is_ipv4_mapped_loopback(&addr.sin6_addr) &&
			addr.sin6_port == htons(bound_port(sk_connect)));

	addrlen = sizeof(addr);
	TEST_RES(getsockname(sk_accept, (struct sockaddr *)&addr, &addrlen),
		 addrlen == sizeof(addr) && addr.sin6_family == AF_INET6 &&
			 is_ipv4_mapped_loopback(&addr.sin6_addr) &&
			 addr.sin6_port == htons(port));

	TEST_SUCC(close(sk_accept));
	TEST_SUCC(close(sk_connect));

	// An IPv6 connection is accepted as usual.
	sk_connect = connect_ipv6_loopback(port);
	addrlen = sizeof(addr);
	sk_accept = TEST_RES(
		accept(sk_listen, (struct sockaddr *)&addr, &addrlen),
		addrlen == sizeof(addr) && addr.sin6_family == AF_INET6 &&
			IN6_IS_ADDR_LOOPBACK(&addr.sin6_addr));

	TEST_SUCC(close(sk_accept));
	TEST_SUCC(close(sk_connect));
	TEST_SUCC(close(sk_listen));
}
END_TEST()

FN_TEST(ipv6_dual_stack_conflicts_with_ipv4)
{
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT,
	};
	struct sockaddr_in addr4 = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};
	int sk6, sk4;

	sk6 = TEST_SUCC(socket(AF_INET6, SOCK_STREAM, 0));
	TEST_SUCC(bind(sk6, (struct sockaddr *)&addr6, sizeof(addr6)));

	addr4.sin_port = htons(bound_port(sk6));
	sk4 = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_ERRNO(bind(sk4, (struct sockaddr *)&addr4, sizeof(addr4)),
		   EADDRINUSE);

	TEST_SUCC(close(sk4));
	TEST_SUCC(close(sk6));
}
END_TEST()

FN_TEST(ipv6_v6only)
{
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT,
	};
	struct sockaddr_in addr4 = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int sk6, sk4, port, v6only = 1;
	socklen_t optlen = sizeof(v6only);

	sk6 = TEST_SUCC(socket(AF_INET6, SOCK_STREAM, 0));
	TEST_SUCC(setsockopt(sk6, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
			     sizeof(v6only)));
	v6only = 0;
	TEST_RES(getsockopt(sk6, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &optlen),
		 optlen == sizeof(v6only) && v6only == 1);
	TEST_SUCC(bind(sk6, (struct sockaddr *)&addr6, sizeof(addr6)));
	TEST_SUCC(listen(sk6, 2));
	port = bound_port(sk6);

	// IPv4 connections are not accepted.
	addr4.sin_port = htons(port);
	sk4 = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_ERRNO(connect(sk4, (struct sockaddr *)&addr4, sizeof(addr4)),
		   ECONNREFUSED);
	TEST_SUCC(close(sk4));

	// The IPv4 unspecified address does not conflict.
	addr4.sin_addr.s_addr = htonl(INADDR_ANY);
	sk4 = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SUCC(bind(sk4, (struct sockaddr *)&addr4, sizeof(addr4)));
	TEST_SUCC(close(sk4));

	TEST_SUCC(close(sk6));
}
END_TEST()

FN_TEST(ipv6_v6only_errors)
{
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	int sk, v6only = 1;
	char short_val = 1;

	sk = TEST_SUCC(socket(AF_INET6, SOCK_STREAM, 0));
	TEST_ERRNO(setsockopt(sk, IPPROTO_IPV6, IPV6_V6ONLY, &short_val,
			      sizeof(short_val)),
		   EINVAL);

	// The option cannot be changed after binding.
	TEST_SUCC(bind(sk, (struct sockaddr *)&addr6, sizeof(addr6)));
	TEST_ERRNO(setsockopt(sk, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
			      sizeof(v6only)),
		   EINVAL);

	TEST_SUCC(close(sk));
}
END_TEST()
