// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

#define BASE_DIR "/ext2/perm_test"
#define TEST_FILE BASE_DIR "/testfile"

FN_SETUP(create_base_dir)
{
	CHECK_WITH(mkdir(BASE_DIR, 0755), _ret == 0 || errno == EEXIST);
}
END_SETUP()

#define USER_UID 1000
#define USER_GID 1000
#define OTHER_GID 2000

/* Runs `op` as an unprivileged user in group `USER_GID` and returns its errno. */
#define ERRNO_AS_USER(op)                                                      \
	({                                                                     \
		int status;                                                    \
		pid_t pid = CHECK(fork());                                     \
		if (pid == 0) {                                                \
			if (setgroups(0, NULL) < 0 ||                          \
			    setresgid(USER_GID, USER_GID, USER_GID) < 0 ||      \
			    setresuid(USER_UID, USER_UID, USER_UID) < 0)        \
				_exit(255);                                    \
			_exit((op) < 0 ? errno : 0);                           \
		}                                                              \
		CHECK(waitpid(pid, &status, 0));                               \
		WEXITSTATUS(status);                                           \
	})

FN_TEST(non_owner_cannot_chmod_or_chown)
{
	CHECK(close(CHECK(creat(TEST_FILE, 0666))));

	TEST_RES(ERRNO_AS_USER(chmod(TEST_FILE, 0777)), _ret == EPERM);
	TEST_RES(ERRNO_AS_USER(chown(TEST_FILE, USER_UID, -1)), _ret == EPERM);
	TEST_RES(ERRNO_AS_USER(chown(TEST_FILE, -1, USER_GID)), _ret == EPERM);

	TEST_SUCC(unlink(TEST_FILE));
}
END_TEST()

FN_TEST(owner_may_only_chgrp_to_own_groups)
{
	struct stat st;

	CHECK(close(CHECK(creat(TEST_FILE, 0644))));
	TEST_SUCC(chown(TEST_FILE, USER_UID, OTHER_GID));

	TEST_RES(ERRNO_AS_USER(chmod(TEST_FILE, 0600)), _ret == 0);
	TEST_RES(ERRNO_AS_USER(chown(TEST_FILE, USER_UID, USER_GID)), _ret == 0);
	TEST_RES(ERRNO_AS_USER(chown(TEST_FILE, -1, OTHER_GID)), _ret == EPERM);
	TEST_RES(ERRNO_AS_USER(chown(TEST_FILE, 0, -1)), _ret == EPERM);
	TEST_RES(stat(TEST_FILE, &st),
		 st.st_uid == USER_UID && st.st_gid == USER_GID);

	TEST_SUCC(unlink(TEST_FILE));
}
END_TEST()

FN_TEST(set_id_bits_are_dropped)
{
	struct stat st;

	CHECK(close(CHECK(creat(TEST_FILE, 0644))));
	TEST_SUCC(chown(TEST_FILE, USER_UID, OTHER_GID));

	/* The owner outside the file's group cannot set the set-group-ID bit. */
	TEST_RES(ERRNO_AS_USER(chmod(TEST_FILE, 06755)), _ret == 0);
	TEST_RES(stat(TEST_FILE, &st), (st.st_mode & 07777) == 04755);

	/* Changing the owner, even to the same IDs, drops the set-user-ID bit. */
	TEST_SUCC(chmod(TEST_FILE, 06755));
	TEST_SUCC(chown(TEST_FILE, -1, -1));
	TEST_RES(stat(TEST_FILE, &st), (st.st_mode & 07777) == 0755);

	TEST_SUCC(unlink(TEST_FILE));
}
END_TEST()

FN_TEST(chown_changes_owner)
{
	int fd = TEST_SUCC(creat(TEST_FILE, 0644));
	TEST_SUCC(close(fd));

	TEST_SUCC(chown(TEST_FILE, 1000, 1000));

	struct stat st;
	TEST_SUCC(stat(TEST_FILE, &st));
	TEST_RES(stat(TEST_FILE, &st), st.st_uid == 1000 && st.st_gid == 1000);

	// Restore ownership to root before cleanup
	TEST_SUCC(chown(TEST_FILE, 0, 0));
	TEST_SUCC(unlink(TEST_FILE));
}
END_TEST()

FN_TEST(chmod_changes_mode)
{
	int fd = TEST_SUCC(creat(TEST_FILE, 0644));
	TEST_SUCC(close(fd));

	TEST_SUCC(chmod(TEST_FILE, 0755));

	struct stat st;
	TEST_RES(stat(TEST_FILE, &st), (st.st_mode & 0777) == 0755);

	TEST_SUCC(unlink(TEST_FILE));
}
END_TEST()

FN_TEST(write_updates_mtime)
{
	int fd = TEST_SUCC(open(TEST_FILE, O_CREAT | O_WRONLY, 0644));
	TEST_SUCC(close(fd));

	struct stat st1;
	TEST_SUCC(stat(TEST_FILE, &st1));

	// Sleep to ensure the timestamp advances
	sleep(1);

	fd = TEST_SUCC(open(TEST_FILE, O_WRONLY));
	TEST_RES(write(fd, "hello", 5), _ret == 5);
	TEST_SUCC(close(fd));

	struct stat st2;
	TEST_RES(stat(TEST_FILE, &st2), st2.st_mtime > st1.st_mtime);

	TEST_SUCC(unlink(TEST_FILE));
}
END_TEST()
