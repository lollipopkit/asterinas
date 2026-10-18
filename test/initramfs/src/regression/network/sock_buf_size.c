// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../common/capability.h"
#include "../common/test.h"

// The minimum buffer sizes (`SOCK_MIN_SNDBUF` and `SOCK_MIN_RCVBUF`) on 64-bit
// Linux.
#define MIN_SNDBUF 4608
#define MIN_RCVBUF 2304

static int wmem_max, rmem_max, wmem_default, rmem_default;

static int read_sysctl(const char *name)
{
	char path[64], buf[32];
	ssize_t len;
	int fd;

	snprintf(path, sizeof(path), "/proc/sys/net/core/%s", name);
	fd = CHECK(open(path, O_RDONLY));
	len = CHECK(read(fd, buf, sizeof(buf) - 1));
	buf[len] = '\0';
	CHECK(close(fd));

	return atoi(buf);
}

// Returns `tcp_rmem[1]`, or its Linux default if the system does not expose it.
static int tcp_rmem_default(void)
{
	int min, def, max;
	FILE *file = fopen("/proc/sys/net/ipv4/tcp_rmem", "r");

	if (file == NULL)
		return 131072;
	CHECK_WITH(fscanf(file, "%d %d %d", &min, &def, &max), _ret == 3);
	CHECK(fclose(file));
	return def;
}

static int write_sysctl(const char *name, const char *value)
{
	char path[64];
	ssize_t len;
	int fd;

	snprintf(path, sizeof(path), "/proc/sys/net/core/%s", name);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	len = write(fd, value, strlen(value));
	close(fd);

	return len < 0 ? -1 : 0;
}

FN_SETUP(sysctls)
{
	wmem_max = read_sysctl("wmem_max");
	rmem_max = read_sysctl("rmem_max");
	wmem_default = read_sysctl("wmem_default");
	rmem_default = read_sysctl("rmem_default");
}
END_SETUP()

static int get_int_opt(int sk, int name)
{
	int val = -1;
	socklen_t len = sizeof(val);

	if (getsockopt(sk, SOL_SOCKET, name, &val, &len) < 0)
		return -1;
	return val;
}

static int set_int_opt(int sk, int name, int val)
{
	return setsockopt(sk, SOL_SOCKET, name, &val, sizeof(val));
}

FN_TEST(sysctl_values)
{
	TEST_RES(wmem_max, _ret >= MIN_SNDBUF);
	TEST_RES(rmem_max, _ret >= MIN_RCVBUF);
	TEST_RES(wmem_default, _ret >= MIN_SNDBUF);
	TEST_RES(rmem_default, _ret >= MIN_RCVBUF);
}
END_TEST()

static int new_socket(int index)
{
	switch (index) {
	case 0:
		return socket(AF_INET, SOCK_STREAM, 0);
	case 1:
		return socket(AF_INET, SOCK_DGRAM, 0);
	case 2:
		return socket(AF_UNIX, SOCK_STREAM, 0);
	case 3:
		return socket(AF_UNIX, SOCK_SEQPACKET, 0);
	default:
		return socket(AF_UNIX, SOCK_DGRAM, 0);
	}
}

#define NR_SOCKET_TYPES 5

FN_TEST(default_sizes)
{
	int sk;

	// UDP and UNIX sockets use the sysctl defaults.
	for (int i = 1; i < NR_SOCKET_TYPES; i++) {
		sk = TEST_SUCC(new_socket(i));
		TEST_RES(get_int_opt(sk, SO_SNDBUF), _ret == wmem_default);
		TEST_RES(get_int_opt(sk, SO_RCVBUF), _ret == rmem_default);
		TEST_SUCC(close(sk));
	}

	// TCP sockets use `tcp_rmem[1]` as the default receive buffer size.
	sk = TEST_SUCC(new_socket(0));
	TEST_RES(get_int_opt(sk, SO_RCVBUF), _ret == tcp_rmem_default());
	TEST_SUCC(close(sk));
}
END_TEST()

FN_TEST(set_and_get)
{
	int sk;

	for (int i = 0; i < NR_SOCKET_TYPES; i++) {
		sk = TEST_SUCC(new_socket(i));

		// The value is doubled.
		TEST_SUCC(set_int_opt(sk, SO_SNDBUF, 10000));
		TEST_RES(get_int_opt(sk, SO_SNDBUF), _ret == 20000);
		TEST_SUCC(set_int_opt(sk, SO_RCVBUF, 10000));
		TEST_RES(get_int_opt(sk, SO_RCVBUF), _ret == 20000);

		// The value is at least the minimum value.
		TEST_SUCC(set_int_opt(sk, SO_SNDBUF, 0));
		TEST_RES(get_int_opt(sk, SO_SNDBUF), _ret == MIN_SNDBUF);
		TEST_SUCC(set_int_opt(sk, SO_RCVBUF, 0));
		TEST_RES(get_int_opt(sk, SO_RCVBUF), _ret == MIN_RCVBUF);
		TEST_SUCC(set_int_opt(sk, SO_SNDBUF, MIN_SNDBUF / 2 - 1));
		TEST_RES(get_int_opt(sk, SO_SNDBUF), _ret == MIN_SNDBUF);

		// The value is clamped to the maximum value. A negative value is
		// treated as a large unsigned value.
		TEST_SUCC(set_int_opt(sk, SO_SNDBUF, wmem_max + 1));
		TEST_RES(get_int_opt(sk, SO_SNDBUF), _ret == wmem_max * 2);
		TEST_SUCC(set_int_opt(sk, SO_RCVBUF, INT_MAX));
		TEST_RES(get_int_opt(sk, SO_RCVBUF), _ret == rmem_max * 2);
		TEST_SUCC(set_int_opt(sk, SO_SNDBUF, -1));
		TEST_RES(get_int_opt(sk, SO_SNDBUF), _ret == wmem_max * 2);
		TEST_SUCC(set_int_opt(sk, SO_RCVBUF, -1));
		TEST_RES(get_int_opt(sk, SO_RCVBUF), _ret == rmem_max * 2);

		// The forcing options cannot be read.
		TEST_ERRNO(get_int_opt(sk, SO_SNDBUFFORCE), ENOPROTOOPT);
		TEST_ERRNO(get_int_opt(sk, SO_RCVBUFFORCE), ENOPROTOOPT);

		TEST_SUCC(close(sk));
	}
}
END_TEST()

FN_TEST(force)
{
	int sk;

	SKIP_TEST_IF(getuid() != 0);

	for (int i = 0; i < NR_SOCKET_TYPES; i++) {
		sk = TEST_SUCC(new_socket(i));

		// The maximum values do not apply.
		TEST_SUCC(set_int_opt(sk, SO_SNDBUFFORCE, wmem_max + 1));
		TEST_RES(get_int_opt(sk, SO_SNDBUF), _ret == wmem_max * 2 + 2);
		TEST_SUCC(set_int_opt(sk, SO_RCVBUFFORCE, INT_MAX));
		TEST_RES(get_int_opt(sk, SO_RCVBUF), _ret == INT_MAX - 1);

		// A negative value is treated as zero.
		TEST_SUCC(set_int_opt(sk, SO_SNDBUFFORCE, -1));
		TEST_RES(get_int_opt(sk, SO_SNDBUF), _ret == MIN_SNDBUF);
		TEST_SUCC(set_int_opt(sk, SO_RCVBUFFORCE, -1));
		TEST_RES(get_int_opt(sk, SO_RCVBUF), _ret == MIN_RCVBUF);

		TEST_SUCC(close(sk));
	}
}
END_TEST()

FN_TEST(sysctl_write)
{
	char old_rmem_max[32], old_wmem_max[32];
	int sk;

	SKIP_TEST_IF(getuid() != 0);

	snprintf(old_rmem_max, sizeof(old_rmem_max), "%d\n", rmem_max);
	snprintf(old_wmem_max, sizeof(old_wmem_max), "%d\n", wmem_max);

	// Values below the minimum values are rejected.
	TEST_ERRNO(write_sysctl("rmem_max", "2303"), EINVAL);
	TEST_ERRNO(write_sysctl("wmem_max", "4607"), EINVAL);
	TEST_ERRNO(write_sysctl("wmem_default", "-1"), EINVAL);
	TEST_RES(read_sysctl("rmem_max"), _ret == rmem_max);

	TEST_SUCC(write_sysctl("rmem_max", "100000\n"));
	TEST_SUCC(write_sysctl("wmem_max", "50000"));
	TEST_RES(read_sysctl("rmem_max"), _ret == 100000);
	TEST_RES(read_sysctl("wmem_max"), _ret == 50000);

	sk = TEST_SUCC(socket(AF_UNIX, SOCK_STREAM, 0));
	TEST_SUCC(set_int_opt(sk, SO_RCVBUF, INT_MAX));
	TEST_RES(get_int_opt(sk, SO_RCVBUF), _ret == 200000);
	TEST_SUCC(set_int_opt(sk, SO_SNDBUF, INT_MAX));
	TEST_RES(get_int_opt(sk, SO_SNDBUF), _ret == 100000);
	TEST_SUCC(close(sk));

	TEST_SUCC(write_sysctl("rmem_max", old_rmem_max));
	TEST_SUCC(write_sysctl("wmem_max", old_wmem_max));
	TEST_RES(read_sysctl("rmem_max"), _ret == rmem_max);
	TEST_RES(read_sysctl("wmem_max"), _ret == wmem_max);
}
END_TEST()

FN_TEST(force_without_cap)
{
	int pid, status;

	SKIP_TEST_IF(getuid() != 0);

	pid = TEST_SUCC(fork());
	if (pid == 0) {
		int sk;

		drop_capability(CAP_NET_ADMIN);
		sk = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
		CHECK_WITH(set_int_opt(sk, SO_SNDBUFFORCE, 10000),
			   _ret < 0 && errno == EPERM);
		CHECK_WITH(set_int_opt(sk, SO_RCVBUFFORCE, 10000),
			   _ret < 0 && errno == EPERM);
		exit(0);
	}

	TEST_RES(waitpid(pid, &status, 0),
		 _ret == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()

// Sends `len`-byte messages on the non-blocking socket until it fails, and
// returns the number of messages sent. Fails if the errno is not `EAGAIN`.
static int send_until_full(int sk, size_t len)
{
	static char buf[65536];
	int count = 0;

	for (;;) {
		ssize_t ret = send(sk, buf, len, MSG_DONTWAIT);

		if (ret < 0 && errno == EAGAIN) {
			errno = 0;
			return count;
		}
		if (ret < 0)
			return -1;
		count++;
	}
}

// Sends data on the non-blocking stream socket until it is full, and returns the
// number of bytes sent.
static ssize_t write_until_full(int sk)
{
	static char buf[65536];
	ssize_t total = 0;

	for (;;) {
		ssize_t ret = send(sk, buf, sizeof(buf), MSG_DONTWAIT);

		if (ret < 0 && errno == EAGAIN) {
			errno = 0;
			return total;
		}
		if (ret < 0)
			return -1;
		total += ret;
	}
}

static int is_writable(int sk)
{
	struct pollfd pfd = { .fd = sk, .events = POLLOUT };

	return poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLOUT);
}

static void drain(int sk)
{
	static char buf[65536];

	while (recv(sk, buf, sizeof(buf), MSG_DONTWAIT) > 0)
		;
}

FN_TEST(udp_recv_buf)
{
	struct sockaddr_in addr = { .sin_family = AF_INET };
	socklen_t addrlen = sizeof(addr);
	char buf[4096];
	int sender, receiver, count;

	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	receiver = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	TEST_SUCC(bind(receiver, (struct sockaddr *)&addr, sizeof(addr)));
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&addr, &addrlen));
	sender = TEST_SUCC(socket(AF_INET, SOCK_DGRAM, 0));
	TEST_SUCC(connect(sender, (struct sockaddr *)&addr, sizeof(addr)));

	// With the default receive buffer, all datagrams are received.
	for (int i = 0; i < 10; i++)
		TEST_RES(send(sender, buf, 1000, 0), _ret == 1000);
	usleep(100 * 1000);
	count = 0;
	while (recv(receiver, buf, sizeof(buf), MSG_DONTWAIT) == 1000)
		count++;
	TEST_RES(count, _ret == 10);

	// With the minimum receive buffer, the datagrams beyond the limit are
	// dropped.
	TEST_SUCC(set_int_opt(receiver, SO_RCVBUF, 0));
	for (int i = 0; i < 10; i++)
		TEST_RES(send(sender, buf, 1000, 0), _ret == 1000);
	usleep(100 * 1000);
	count = 0;
	while (recv(receiver, buf, sizeof(buf), MSG_DONTWAIT) == 1000)
		count++;
	TEST_RES(count, _ret >= 1 && _ret <= MIN_RCVBUF / 1000);

	// After the datagrams are received, new datagrams are queued again.
	TEST_RES(send(sender, buf, 1000, 0), _ret == 1000);
	usleep(100 * 1000);
	TEST_RES(recv(receiver, buf, sizeof(buf), MSG_DONTWAIT), _ret == 1000);
	TEST_ERRNO(recv(receiver, buf, sizeof(buf), MSG_DONTWAIT), EAGAIN);

	TEST_SUCC(close(sender));
	TEST_SUCC(close(receiver));
}
END_TEST()

FN_TEST(unix_dgram_send_buf)
{
	static char buf[8192];
	int fds[2], count, sndbuf;

	TEST_SUCC(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds));

	// Messages that do not fit in the send buffer are rejected.
	TEST_SUCC(set_int_opt(fds[0], SO_SNDBUF, 0));
	TEST_ERRNO(send(fds[0], buf, MIN_SNDBUF - 31, 0), EMSGSIZE);
	TEST_RES(send(fds[0], buf, MIN_SNDBUF - 32, 0),
		 _ret == MIN_SNDBUF - 32);
	TEST_ERRNO(send(fds[0], buf, 1, MSG_DONTWAIT), EAGAIN);
	drain(fds[1]);

	// The sender stops when the memory charged for the queued messages
	// reaches the send buffer size. The charged memory includes overhead, so
	// fewer bytes are sent.
	TEST_SUCC(set_int_opt(fds[0], SO_SNDBUF, 16384));
	sndbuf = get_int_opt(fds[0], SO_SNDBUF);
	count = TEST_RES(send_until_full(fds[0], 1000),
			 _ret >= sndbuf / 4096 && _ret * 1000 <= sndbuf);
	TEST_RES(is_writable(fds[0]), _ret == 0);

	// Receiving a message frees the send buffer.
	TEST_RES(recv(fds[1], buf, sizeof(buf), 0), _ret == 1000);
	TEST_RES(send(fds[0], buf, 1000, MSG_DONTWAIT), _ret == 1000);
	TEST_ERRNO(send(fds[0], buf, 1000, MSG_DONTWAIT), EAGAIN);

	// Increasing the send buffer allows more messages.
	TEST_SUCC(set_int_opt(fds[0], SO_SNDBUF, 32768));
	TEST_RES(send_until_full(fds[0], 1000), _ret > 0);

	drain(fds[1]);
	TEST_RES(is_writable(fds[0]), _ret == 1);
	TEST_RES(count, _ret > 0);

	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()

FN_TEST(unix_dgram_queue_len)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	socklen_t addrlen = sizeof(addr);
	int receiver, sender, max_qlen;
	char buf[16];
	ssize_t len;
	int fd;

	fd = TEST_SUCC(open("/proc/sys/net/unix/max_dgram_qlen", O_RDONLY));
	len = TEST_RES(read(fd, buf, sizeof(buf) - 1), _ret > 0);
	buf[len < 0 ? 0 : len] = '\0';
	max_qlen = atoi(buf);
	TEST_SUCC(close(fd));

	// Bind to an autobind address.
	receiver = TEST_SUCC(socket(AF_UNIX, SOCK_DGRAM, 0));
	TEST_SUCC(
		bind(receiver, (struct sockaddr *)&addr, sizeof(sa_family_t)));
	TEST_SUCC(getsockname(receiver, (struct sockaddr *)&addr, &addrlen));
	sender = TEST_SUCC(socket(AF_UNIX, SOCK_DGRAM, 0));
	TEST_SUCC(connect(sender, (struct sockaddr *)&addr, addrlen));
	TEST_SUCC(set_int_opt(sender, SO_SNDBUF, INT_MAX));

	// Like Linux, the receive queue of a socket that is not connected to the
	// sender holds at most `net.unix.max_dgram_qlen + 1` messages. Each
	// message is charged less than 800 bytes to the send buffer.
	if ((max_qlen + 1) * 800 < get_int_opt(sender, SO_SNDBUF)) {
		TEST_RES(send_until_full(sender, 1), _ret == max_qlen + 1);
		TEST_RES(recv(receiver, buf, 1, 0), _ret == 1);
		TEST_RES(send_until_full(sender, 1), _ret == 1);
	}

	TEST_SUCC(close(sender));
	TEST_SUCC(close(receiver));
}
END_TEST()

FN_TEST(unix_stream_send_buf)
{
	ssize_t small, large;
	int fds[2];
	char buf[1];

	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

	large = TEST_RES(write_until_full(fds[0]), _ret > 4 * MIN_SNDBUF);
	drain(fds[1]);

	// The bytes queued by the sender are limited by its send buffer.
	TEST_SUCC(set_int_opt(fds[0], SO_SNDBUF, 0));
	small = TEST_RES(write_until_full(fds[0]),
			 _ret > 0 && _ret <= MIN_SNDBUF);
	TEST_RES(large, _ret > small);
	TEST_RES(is_writable(fds[0]), _ret == 0);

	// Increasing the send buffer allows more bytes.
	TEST_SUCC(set_int_opt(fds[0], SO_SNDBUF, 65536));
	TEST_RES(is_writable(fds[0]), _ret == 1);
	TEST_RES(send(fds[0], buf, 1, MSG_DONTWAIT), _ret == 1);
	TEST_RES(write_until_full(fds[0]), _ret > MIN_SNDBUF);
	TEST_RES(is_writable(fds[0]), _ret == 0);

	drain(fds[1]);
	TEST_RES(is_writable(fds[0]), _ret == 1);

	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()

FN_TEST(unix_seqpacket_send_buf)
{
	static char buf[8192];
	int fds[2];

	TEST_SUCC(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));

	TEST_SUCC(set_int_opt(fds[0], SO_SNDBUF, 0));
	TEST_ERRNO(send(fds[0], buf, MIN_SNDBUF - 31, 0), EMSGSIZE);
	TEST_RES(send(fds[0], buf, MIN_SNDBUF - 32, 0),
		 _ret == MIN_SNDBUF - 32);
	TEST_ERRNO(send(fds[0], buf, MIN_SNDBUF - 32, MSG_DONTWAIT), EAGAIN);

	TEST_RES(recv(fds[1], buf, sizeof(buf), 0), _ret == MIN_SNDBUF - 32);
	TEST_RES(send(fds[0], buf, MIN_SNDBUF - 32, MSG_DONTWAIT),
		 _ret == MIN_SNDBUF - 32);

	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()

// Sends on the non-blocking TCP socket until the data cannot be transferred
// any more, and returns the number of bytes sent.
static ssize_t tcp_send_until_full(int sk)
{
	ssize_t total = 0, sent;

	do {
		usleep(50 * 1000);
		sent = write_until_full(sk);
		if (sent < 0)
			return -1;
		total += sent;
	} while (sent > 0);

	return total;
}

FN_TEST(tcp_buf)
{
	struct sockaddr_in addr = { .sin_family = AF_INET };
	socklen_t addrlen = sizeof(addr);
	int listener, client, server;
	ssize_t small;

	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	listener = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SUCC(bind(listener, (struct sockaddr *)&addr, sizeof(addr)));
	TEST_SUCC(getsockname(listener, (struct sockaddr *)&addr, &addrlen));
	TEST_SUCC(listen(listener, 2));

	// The accepted socket inherits the buffer sizes of the listener.
	TEST_SUCC(set_int_opt(listener, SO_SNDBUF, 8192));
	TEST_SUCC(set_int_opt(listener, SO_RCVBUF, 20000));

	// A small receive buffer limits the data in flight.
	client = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SUCC(set_int_opt(client, SO_RCVBUF, 0));
	TEST_SUCC(connect(client, (struct sockaddr *)&addr, sizeof(addr)));
	server = TEST_SUCC(accept(listener, NULL, NULL));
	TEST_RES(get_int_opt(server, SO_SNDBUF), _ret == 16384);
	TEST_RES(get_int_opt(server, SO_RCVBUF), _ret == 40000);
	TEST_RES(get_int_opt(client, SO_RCVBUF), _ret == MIN_RCVBUF);
	small = TEST_RES(tcp_send_until_full(server), _ret > 0);
	TEST_SUCC(close(client));
	TEST_SUCC(close(server));

	client = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_SUCC(set_int_opt(client, SO_RCVBUF, 65536));
	TEST_SUCC(connect(client, (struct sockaddr *)&addr, sizeof(addr)));
	server = TEST_SUCC(accept(listener, NULL, NULL));
	TEST_RES(tcp_send_until_full(server), _ret > small);
	TEST_SUCC(close(client));
	TEST_SUCC(close(server));

	TEST_SUCC(close(listener));
}
END_TEST()
