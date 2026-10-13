// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../common/test.h"

// `MSG_WAITALL` makes a receive on a stream socket wait until the buffer is
// full, unless the waiting is interrupted.

#define LEN 1000
#define HALF (LEN / 2)

static char data[LEN];

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

static void set_recv_timeout(int fd, long usec)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = usec };

	CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)));
}

static long elapsed_ms(struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) * 1000 +
	       (now.tv_nsec - start->tv_nsec) / 1000000;
}

struct sender {
	int fd;
	int chunk;
	int count;
	long interval_us;
};

// Sends `count` chunks of `data`, sleeping before each chunk.
static void *send_chunks(void *arg)
{
	struct sender *sender = arg;

	for (int i = 0; i < sender->count; i++) {
		usleep(sender->interval_us);
		send(sender->fd, data + i * sender->chunk, sender->chunk, 0);
	}
	return NULL;
}

FN_SETUP(data)
{
	for (int i = 0; i < LEN; i++)
		data[i] = i;
}
END_SETUP()

FN_TEST(tcp_wait_for_all)
{
	int client, server;
	char buf[LEN];
	pthread_t thread;
	struct sender sender;

	tcp_pair(&client, &server);
	sender = (struct sender){ client, HALF, 2, 100 * 1000 };

	TEST_SUCC(pthread_create(&thread, NULL, send_chunks, &sender));
	TEST_RES(recv(server, buf, LEN, MSG_WAITALL),
		 _ret == LEN && memcmp(buf, data, LEN) == 0);
	TEST_SUCC(pthread_join(thread, NULL));

	TEST_SUCC(close(server));
	TEST_SUCC(close(client));
}
END_TEST()

FN_TEST(tcp_stop_at_eof)
{
	int client, server;
	char buf[LEN];

	tcp_pair(&client, &server);

	TEST_RES(send(client, data, HALF, 0), _ret == HALF);
	TEST_SUCC(shutdown(client, SHUT_WR));
	TEST_RES(recv(server, buf, LEN, MSG_WAITALL),
		 _ret == HALF && memcmp(buf, data, HALF) == 0);

	TEST_SUCC(close(server));
	TEST_SUCC(close(client));
}
END_TEST()

FN_TEST(tcp_stop_at_timeout)
{
	int client, server;
	char buf[LEN];

	tcp_pair(&client, &server);
	set_recv_timeout(server, 100 * 1000);

	TEST_RES(send(client, data, HALF, 0), _ret == HALF);
	TEST_RES(recv(server, buf, LEN, MSG_WAITALL),
		 _ret == HALF && memcmp(buf, data, HALF) == 0);

	TEST_SUCC(close(server));
	TEST_SUCC(close(client));
}
END_TEST()

FN_TEST(tcp_dont_wait)
{
	int client, server;
	char buf[LEN];

	tcp_pair(&client, &server);

	// The data must have arrived at the receiver.
	TEST_RES(send(client, data, HALF, 0), _ret == HALF);
	usleep(100 * 1000);
	TEST_RES(recv(server, buf, LEN, MSG_WAITALL | MSG_DONTWAIT),
		 _ret == HALF && memcmp(buf, data, HALF) == 0);

	TEST_SUCC(close(server));
	TEST_SUCC(close(client));
}
END_TEST()

FN_TEST(tcp_timeout_is_total)
{
	int client, server;
	char buf[LEN];
	pthread_t thread;
	struct sender sender;
	struct timespec start;

	tcp_pair(&client, &server);
	set_recv_timeout(server, 350 * 1000);
	sender = (struct sender){ client, LEN / 10, 10, 100 * 1000 };

	// The timeout applies to the whole call rather than each wait, so the
	// call returns before all the chunks are sent.
	TEST_SUCC(pthread_create(&thread, NULL, send_chunks, &sender));
	clock_gettime(CLOCK_MONOTONIC, &start);
	TEST_RES(recv(server, buf, LEN, MSG_WAITALL),
		 _ret > 0 && _ret < LEN && memcmp(buf, data, _ret) == 0 &&
			 elapsed_ms(&start) < 800);
	TEST_SUCC(pthread_join(thread, NULL));

	TEST_SUCC(close(server));
	TEST_SUCC(close(client));
}
END_TEST()

FN_TEST(unix_stream_wait_for_all)
{
	int fds[2];
	char buf[LEN];
	pthread_t thread;
	struct sender sender;

	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
	sender = (struct sender){ fds[1], HALF, 2, 100 * 1000 };

	TEST_SUCC(pthread_create(&thread, NULL, send_chunks, &sender));
	TEST_RES(recv(fds[0], buf, LEN, MSG_WAITALL),
		 _ret == LEN && memcmp(buf, data, LEN) == 0);
	TEST_SUCC(pthread_join(thread, NULL));

	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()

FN_TEST(unix_stream_stop_at_fds)
{
	int fds[2];
	char buf[LEN];
	char control[CMSG_SPACE(sizeof(int))];
	struct iovec iov = { .iov_base = data, .iov_len = HALF };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	int passed_fd = 0;

	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof(int));
	TEST_RES(sendmsg(fds[1], &msg, 0), _ret == HALF);
	TEST_RES(send(fds[1], data + HALF, HALF, 0), _ret == HALF);

	// Receiving stops once file descriptors are received.
	iov.iov_base = buf;
	iov.iov_len = LEN;
	msg.msg_controllen = sizeof(control);
	TEST_RES(recvmsg(fds[0], &msg, MSG_WAITALL),
		 _ret == HALF && memcmp(buf, data, HALF) == 0 &&
			 CMSG_FIRSTHDR(&msg) != NULL);
	TEST_SUCC(close(*(int *)CMSG_DATA(CMSG_FIRSTHDR(&msg))));

	TEST_RES(recv(fds[0], buf, LEN, MSG_WAITALL | MSG_DONTWAIT),
		 _ret == HALF && memcmp(buf, data + HALF, HALF) == 0);

	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()

FN_TEST(unix_seqpacket_ignores_wait_all)
{
	int fds[2];
	char buf[LEN];

	TEST_SUCC(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));

	TEST_RES(send(fds[1], data, HALF, 0), _ret == HALF);
	TEST_RES(send(fds[1], data + HALF, HALF, 0), _ret == HALF);
	TEST_RES(recv(fds[0], buf, LEN, MSG_WAITALL),
		 _ret == HALF && memcmp(buf, data, HALF) == 0);

	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()
