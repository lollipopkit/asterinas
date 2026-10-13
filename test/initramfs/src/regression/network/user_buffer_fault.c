// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../common/test.h"

// The kernel copies socket data while holding spin locks. These tests check
// that page faults on user buffers are handled correctly in that case.

#define PAGE_SIZE 4096
#define DATA_LEN 1000

static char data[DATA_LEN];
static char zeros[DATA_LEN];
static int tcp_client, tcp_server;
static int udp_client, udp_server;

// Returns a buffer whose pages have never been touched.
static char *fresh_buffer(size_t len)
{
	char *buf = mmap(NULL, len, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK_WITH(buf, buf != MAP_FAILED);
	return buf;
}

// Receives exactly `len` bytes from a stream socket.
static ssize_t recv_all(int fd, char *buf, size_t len)
{
	size_t total = 0;

	while (total < len) {
		ssize_t n = recv(fd, buf + total, len - total, 0);
		if (n <= 0)
			return n;
		total += n;
	}
	return total;
}

FN_SETUP(sockets)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t addrlen = sizeof(addr);
	int listener;

	for (int i = 0; i < DATA_LEN; i++)
		data[i] = i;

	listener = CHECK(socket(AF_INET, SOCK_STREAM, 0));
	CHECK(bind(listener, (struct sockaddr *)&addr, sizeof(addr)));
	CHECK(listen(listener, 1));
	CHECK(getsockname(listener, (struct sockaddr *)&addr, &addrlen));
	tcp_client = CHECK(socket(AF_INET, SOCK_STREAM, 0));
	CHECK(connect(tcp_client, (struct sockaddr *)&addr, sizeof(addr)));
	tcp_server = CHECK(accept(listener, NULL, NULL));
	CHECK(close(listener));

	addr.sin_port = 0;
	udp_server = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
	CHECK(bind(udp_server, (struct sockaddr *)&addr, sizeof(addr)));
	addrlen = sizeof(addr);
	CHECK(getsockname(udp_server, (struct sockaddr *)&addr, &addrlen));
	udp_client = CHECK(socket(AF_INET, SOCK_DGRAM, 0));
	CHECK(connect(udp_client, (struct sockaddr *)&addr, sizeof(addr)));
}
END_SETUP()

FN_TEST(tcp_recv_to_fresh_buffer)
{
	char *buf = fresh_buffer(PAGE_SIZE);

	TEST_RES(send(tcp_client, data, DATA_LEN, 0), _ret == DATA_LEN);
	TEST_RES(recv(tcp_server, buf, PAGE_SIZE, 0),
		 _ret == DATA_LEN && memcmp(buf, data, DATA_LEN) == 0);

	TEST_SUCC(munmap(buf, PAGE_SIZE));
}
END_TEST()

FN_TEST(tcp_send_from_fresh_buffer)
{
	char *buf = fresh_buffer(PAGE_SIZE);
	char out[DATA_LEN];

	// The untouched pages read as zeros.
	memset(out, 0xff, sizeof(out));
	TEST_RES(send(tcp_client, buf, DATA_LEN, 0), _ret == DATA_LEN);
	TEST_RES(recv_all(tcp_server, out, DATA_LEN),
		 _ret == DATA_LEN && out[0] == 0 && out[DATA_LEN - 1] == 0);

	TEST_SUCC(munmap(buf, PAGE_SIZE));
}
END_TEST()

FN_TEST(tcp_recv_to_bad_buffer)
{
	char out[DATA_LEN];

	TEST_RES(send(tcp_client, data, DATA_LEN, 0), _ret == DATA_LEN);
	TEST_ERRNO(recv(tcp_server, NULL, DATA_LEN, 0), EFAULT);

	// The data are not consumed.
	TEST_RES(recv_all(tcp_server, out, DATA_LEN),
		 _ret == DATA_LEN && memcmp(out, data, DATA_LEN) == 0);
}
END_TEST()

FN_TEST(tcp_recv_across_inaccessible_page)
{
	char *buf = fresh_buffer(2 * PAGE_SIZE);
	char out[DATA_LEN];
	const int head = 100;
	int received, recv_errno;

	TEST_SUCC(mprotect(buf + PAGE_SIZE, PAGE_SIZE, PROT_NONE));

	// Like Linux, data that are partially copied before the inaccessible
	// page are not received, so the call fails with `EFAULT`. However, a
	// short read is also possible if the data are split into multiple
	// chunks internally. Either way, no data should be lost.
	TEST_RES(send(tcp_client, data, DATA_LEN, 0), _ret == DATA_LEN);
	received = recv(tcp_server, buf + PAGE_SIZE - head, DATA_LEN, 0);
	recv_errno = received < 0 ? errno : 0;
	TEST_RES(recv_errno, recv_errno == 0 || recv_errno == EFAULT);
	if (received < 0)
		received = 0;
	TEST_RES(received, received <= head && memcmp(buf + PAGE_SIZE - head,
						      data, received) == 0);

	TEST_RES(recv_all(tcp_server, out, DATA_LEN - received),
		 _ret == DATA_LEN - received &&
			 memcmp(out, data + received, DATA_LEN - received) ==
				 0);

	TEST_SUCC(munmap(buf, 2 * PAGE_SIZE));
}
END_TEST()

FN_TEST(udp_recv_to_fresh_buffer)
{
	char *buf = fresh_buffer(PAGE_SIZE);

	TEST_RES(send(udp_client, data, DATA_LEN, 0), _ret == DATA_LEN);
	TEST_RES(recv(udp_server, buf, PAGE_SIZE, 0),
		 _ret == DATA_LEN && memcmp(buf, data, DATA_LEN) == 0);

	TEST_SUCC(munmap(buf, PAGE_SIZE));
}
END_TEST()

FN_TEST(udp_send_from_fresh_buffer)
{
	char *buf = fresh_buffer(PAGE_SIZE);
	char out[DATA_LEN];

	memset(out, 0xff, sizeof(out));
	TEST_RES(send(udp_client, buf, DATA_LEN, 0), _ret == DATA_LEN);
	TEST_RES(recv(udp_server, out, DATA_LEN, 0),
		 _ret == DATA_LEN && out[0] == 0 && out[DATA_LEN - 1] == 0);

	TEST_SUCC(munmap(buf, PAGE_SIZE));
}
END_TEST()

FN_TEST(udp_send_from_bad_buffer)
{
	// No packet is sent.
	TEST_ERRNO(send(udp_client, NULL, DATA_LEN, 0), EFAULT);
	TEST_ERRNO(recv(udp_server, data, DATA_LEN, MSG_DONTWAIT), EAGAIN);
}
END_TEST()

static volatile int stop_mmap_loop;

// Keeps the lock of the address space busy, so page faults may need to wait.
static void *mmap_loop(void *arg)
{
	(void)arg;
	while (!stop_mmap_loop) {
		void *p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p != MAP_FAILED)
			munmap(p, PAGE_SIZE);
	}
	return NULL;
}

FN_TEST(fresh_buffers_with_contention)
{
	pthread_t thread;
	int mismatches = 0;
	char out[DATA_LEN];

	stop_mmap_loop = 0;
	TEST_SUCC(pthread_create(&thread, NULL, mmap_loop, NULL));

	for (int i = 0; i < 2000; i++) {
		char *buf = fresh_buffer(3 * PAGE_SIZE);

		CHECK_WITH(send(tcp_client, data, DATA_LEN, 0),
			   _ret == DATA_LEN);
		CHECK_WITH(recv_all(tcp_server, buf, DATA_LEN),
			   _ret == DATA_LEN);
		mismatches += memcmp(buf, data, DATA_LEN) != 0;

		CHECK_WITH(send(tcp_client, buf + PAGE_SIZE, DATA_LEN, 0),
			   _ret == DATA_LEN);
		CHECK_WITH(recv_all(tcp_server, out, DATA_LEN),
			   _ret == DATA_LEN);
		// The untouched pages read as zeros.
		mismatches += memcmp(out, zeros, DATA_LEN) != 0;

		CHECK_WITH(send(udp_client, data, DATA_LEN, 0),
			   _ret == DATA_LEN);
		CHECK_WITH(recv(udp_server, buf + 2 * PAGE_SIZE, PAGE_SIZE, 0),
			   _ret == DATA_LEN);
		mismatches += memcmp(buf + 2 * PAGE_SIZE, data, DATA_LEN) != 0;

		CHECK(munmap(buf, 3 * PAGE_SIZE));
	}

	stop_mmap_loop = 1;
	TEST_SUCC(pthread_join(thread, NULL));
	TEST_RES(mismatches, mismatches == 0);
}
END_TEST()
