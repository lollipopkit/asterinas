// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <signal.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "../common/test.h"

FN_SETUP(ignore_sigpipe)
{
	CHECK_WITH(signal(SIGPIPE, SIG_IGN), _ret != SIG_ERR);
}
END_SETUP()

FN_TEST(writev_one_message)
{
	struct iovec iov[2] = {
		{ .iov_base = "ab", .iov_len = 2 },
		{ .iov_base = "cde", .iov_len = 3 },
	};
	int types[2] = { SOCK_DGRAM, SOCK_SEQPACKET };
	char buf[8];
	int fds[2];

	for (int i = 0; i < 2; i++) {
		TEST_SUCC(socketpair(AF_UNIX, types[i], 0, fds));

		// All the buffers are sent as one message.
		TEST_RES(writev(fds[0], iov, 2), _ret == 5);
		TEST_RES(recv(fds[1], buf, sizeof(buf), MSG_DONTWAIT),
			 _ret == 5 && memcmp(buf, "abcde", 5) == 0);
		TEST_ERRNO(recv(fds[1], buf, sizeof(buf), MSG_DONTWAIT),
			   EAGAIN);

		TEST_SUCC(close(fds[0]));
		TEST_SUCC(close(fds[1]));
	}
}
END_TEST()

FN_TEST(readv_one_message)
{
	char buf1[2], buf2[2], buf3[8];
	struct iovec iov[2] = {
		{ .iov_base = buf1, .iov_len = sizeof(buf1) },
		{ .iov_base = buf2, .iov_len = sizeof(buf2) },
	};
	int types[2] = { SOCK_DGRAM, SOCK_SEQPACKET };
	int fds[2];

	for (int i = 0; i < 2; i++) {
		TEST_SUCC(socketpair(AF_UNIX, types[i], 0, fds));

		// One message is received into all the buffers, and the rest
		// of the message is discarded.
		TEST_RES(send(fds[0], "abcde", 5, 0), _ret == 5);
		TEST_RES(send(fds[0], "xyz", 3, 0), _ret == 3);
		TEST_RES(readv(fds[1], iov, 2),
			 _ret == 4 && memcmp(buf1, "ab", 2) == 0 &&
				 memcmp(buf2, "cd", 2) == 0);
		TEST_RES(recv(fds[1], buf3, sizeof(buf3), MSG_DONTWAIT),
			 _ret == 3 && memcmp(buf3, "xyz", 3) == 0);

		TEST_SUCC(close(fds[0]));
		TEST_SUCC(close(fds[1]));
	}
}
END_TEST()

FN_TEST(rw_no_data)
{
	struct iovec iov = { .iov_base = "", .iov_len = 0 };
	char buf[8];
	int fds[2];
	int sk;

	// Like Linux, nothing is sent if there are no data, and no errors are
	// reported.
	TEST_SUCC(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds));
	TEST_RES(writev(fds[0], NULL, 0), _ret == 0);
	TEST_RES(writev(fds[0], &iov, 1), _ret == 0);
	TEST_ERRNO(recv(fds[1], buf, sizeof(buf), MSG_DONTWAIT), EAGAIN);
	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));

	sk = TEST_SUCC(socket(AF_INET, SOCK_STREAM, 0));
	TEST_RES(writev(sk, NULL, 0), _ret == 0);
	TEST_SUCC(close(sk));

	// Nothing is received if there are no buffers.
	TEST_SUCC(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds));
	TEST_RES(send(fds[0], "a", 1, 0), _ret == 1);
	TEST_RES(readv(fds[1], NULL, 0), _ret == 0);
	TEST_RES(readv(fds[1], &iov, 1), _ret == 0);
	TEST_RES(recv(fds[1], buf, sizeof(buf), MSG_DONTWAIT), _ret == 1);
	TEST_SUCC(close(fds[0]));
	TEST_SUCC(close(fds[1]));
}
END_TEST()
