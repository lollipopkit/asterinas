// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../common/test.h"

#define ROOT "/sys/devices/system/cpu"
#define MAX_CPUS 1024
#define BUF_SIZE 8192

struct cpus {
	bool has[MAX_CPUS];
};

static struct cpus possible, online, present;
static int nr_cpu_ids;

static int count_cpus(const struct cpus *s)
{
	int n = 0;

	for (int i = 0; i < MAX_CPUS; i++)
		n += s->has[i];
	return n;
}

static bool is_subset(const struct cpus *a, const struct cpus *b)
{
	for (int i = 0; i < MAX_CPUS; i++)
		if (a->has[i] && !b->has[i])
			return false;
	return true;
}

static bool is_equal(const struct cpus *a, const struct cpus *b)
{
	return is_subset(a, b) && is_subset(b, a);
}

static int last_cpu(const struct cpus *s)
{
	for (int i = MAX_CPUS - 1; i >= 0; i--)
		if (s->has[i])
			return i;
	return -1;
}

/*
 * Reads a whole file as text. Linux appends a NUL byte to the CPU mask files,
 * which is dropped here.
 */
static int read_text(const char *path, char *buf)
{
	int fd = open(path, O_RDONLY);
	int len = 0;
	ssize_t n;

	if (fd < 0)
		return -1;
	while ((n = read(fd, buf + len, BUF_SIZE - 1 - len)) > 0)
		len += n;
	close(fd);
	if (n < 0)
		return -1;
	while (len > 0 && buf[len - 1] == '\0')
		len--;
	buf[len] = '\0';
	return len;
}

static int parse_uint(const char **s)
{
	int v = 0;

	if (!isdigit((unsigned char)**s))
		return -1;
	/* No leading zeros. */
	if (**s == '0' && isdigit((unsigned char)(*s)[1]))
		return -1;
	while (isdigit((unsigned char)**s)) {
		v = v * 10 + (**s - '0');
		if (v >= MAX_CPUS)
			return -1;
		(*s)++;
	}
	return v;
}

/*
 * Parses a CPU list such as "0,2-3,5\n". Ranges must be ascending and
 * separated by gaps, and a single CPU must not be written as a range.
 */
static int parse_list(const char *s, struct cpus *set)
{
	int prev_end = -2;

	memset(set, 0, sizeof(*set));
	while (*s != '\n') {
		int start, end;

		if (prev_end != -2 && *s++ != ',')
			return -1;
		start = end = parse_uint(&s);
		if (start < 0)
			return -1;
		if (*s == '-') {
			s++;
			end = parse_uint(&s);
			if (end <= start)
				return -1;
		}
		if (start <= prev_end + 1)
			return -1;
		for (int i = start; i <= end; i++)
			set->has[i] = true;
		prev_end = end;
	}
	return s[1] == '\0' ? 0 : -1;
}

/* Returns the value of a lowercase hexadecimal digit, or -1. */
static int hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

/*
 * Parses a CPU mask of `nr_bits` bits such as "00,00000001\n": 32-bit hex
 * chunks, most significant first, where the first chunk is as wide as its
 * bits need and the others are 8 digits wide.
 */
static int parse_mask(const char *s, int nr_bits, struct cpus *set)
{
	int nr_chunks = (nr_bits + 31) / 32;
	int top_bits = nr_bits % 32 ? nr_bits % 32 : 32;

	memset(set, 0, sizeof(*set));
	for (int chunk = nr_chunks - 1; chunk >= 0; chunk--) {
		int width = chunk == nr_chunks - 1 ? (top_bits + 3) / 4 : 8;
		unsigned long val = 0;

		if (chunk != nr_chunks - 1 && *s++ != ',')
			return -1;
		for (int i = 0; i < width; i++, s++) {
			int digit = hex_digit(*s);

			if (digit < 0)
				return -1;
			val = val * 16 + digit;
		}
		for (int bit = 0; bit < 32; bit++) {
			int cpu = chunk * 32 + bit;

			if (!(val & (1UL << bit)))
				continue;
			if (cpu >= nr_bits || cpu >= MAX_CPUS)
				return -1;
			set->has[cpu] = true;
		}
	}
	return strcmp(s, "\n") == 0 ? 0 : -1;
}

static int read_list(const char *path, struct cpus *set)
{
	char buf[BUF_SIZE];

	if (read_text(path, buf) < 0)
		return -1;
	return parse_list(buf, set);
}

static int read_mask(const char *path, struct cpus *set)
{
	char buf[BUF_SIZE];

	if (read_text(path, buf) < 0)
		return -1;
	return parse_mask(buf, nr_cpu_ids, set);
}

/* Reads an integer printed with "%d\n". */
static int read_int(const char *path, int *val)
{
	char buf[BUF_SIZE];
	char *end;

	if (read_text(path, buf) < 0)
		return -1;
	errno = 0;
	*val = strtol(buf, &end, 10);
	if (errno || end == buf || strcmp(end, "\n") != 0)
		return -1;
	return 0;
}

static bool is_read_only(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && (st.st_mode & 0777) == 0444;
}

/*
 * Some libc functions may leave `errno` set when they succeed, which the
 * `TEST_*()` macros would report as failures.
 */
static long nprocs(int name)
{
	long n = sysconf(name);

	if (n > 0)
		errno = 0;
	return n;
}

static bool resolves_to(const char *path, const char *expected)
{
	char resolved[PATH_MAX];
	bool ok = realpath(path, resolved) && strcmp(resolved, expected) == 0;

	if (ok)
		errno = 0;
	return ok;
}

static const char *topology_path(int cpu, const char *file)
{
	static char path[PATH_MAX];

	snprintf(path, sizeof(path), ROOT "/cpu%d/topology/%s", cpu, file);
	return path;
}

/* Reads a mask file and its "_list" twin, which must agree. */
static int read_topology_set(int cpu, const char *name, struct cpus *set)
{
	char list_name[64];
	struct cpus list;

	snprintf(list_name, sizeof(list_name), "%s_list", name);
	if (read_mask(topology_path(cpu, name), set) < 0 ||
	    read_list(topology_path(cpu, list_name), &list) < 0)
		return -1;
	return is_equal(set, &list) ? 0 : -1;
}

static int read_topology_id(int cpu, const char *name)
{
	int val;

	if (read_int(topology_path(cpu, name), &val) < 0)
		return INT_MIN;
	return val;
}

FN_SETUP(root_sets)
{
	CHECK(read_list(ROOT "/possible", &possible));
	CHECK(read_list(ROOT "/online", &online));
	CHECK(read_list(ROOT "/present", &present));
	nr_cpu_ids = last_cpu(&possible) + 1;
	CHECK_WITH(nr_cpu_ids, _ret > 0);
}
END_SETUP()

FN_TEST(root_files)
{
	const char *const files[] = { "online",	 "possible", "present",
				      "offline", "isolated", "kernel_max" };
	struct cpus set;

	for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		char path[PATH_MAX];

		snprintf(path, sizeof(path), ROOT "/%s", files[i]);
		TEST_RES(is_read_only(path), _ret);
	}
	TEST_RES(read_list(ROOT "/isolated", &set), _ret == 0);
	/* Older Linux versions lack these files. */
	if (access(ROOT "/housekeeping", F_OK) == 0)
		TEST_RES(read_list(ROOT "/housekeeping", &set), _ret == 0);
	if (access(ROOT "/enabled", F_OK) == 0)
		TEST_RES(read_list(ROOT "/enabled", &set),
			 _ret == 0 && is_subset(&set, &present));
	TEST_RES(count_cpus(&online), _ret > 0 &&
					      is_subset(&online, &present) &&
					      is_subset(&present, &possible));
}
END_TEST()

FN_TEST(offline)
{
	struct cpus offline, expected;

	for (int i = 0; i < MAX_CPUS; i++)
		expected.has[i] = possible.has[i] && !online.has[i];
	TEST_RES(read_list(ROOT "/offline", &offline),
		 _ret == 0 && is_equal(&offline, &expected));
}
END_TEST()

FN_TEST(kernel_max)
{
	int kernel_max;

	TEST_RES(read_int(ROOT "/kernel_max", &kernel_max),
		 _ret == 0 && kernel_max >= last_cpu(&possible));
}
END_TEST()

FN_TEST(sysconf)
{
	TEST_RES(nprocs(_SC_NPROCESSORS_ONLN), _ret == count_cpus(&online));
	TEST_RES(nprocs(_SC_NPROCESSORS_CONF), _ret == count_cpus(&possible));
}
END_TEST()

FN_TEST(affinity)
{
	cpu_set_t mask;
	struct cpus affinity = { 0 };

	TEST_SUCC(sched_getaffinity(0, sizeof(mask), &mask));
	for (int i = 0; i < MAX_CPUS && i < CPU_SETSIZE; i++)
		affinity.has[i] = CPU_ISSET(i, &mask);
	TEST_RES(count_cpus(&affinity),
		 _ret > 0 && is_subset(&affinity, &online));
}
END_TEST()

FN_TEST(cpu_devices)
{
	struct cpus dirs = { 0 };
	struct dirent *entry;
	DIR *dir;

	dir = TEST_RES(opendir(ROOT), _ret != NULL);
	while (dir && (entry = readdir(dir))) {
		unsigned int cpu;
		int len = 0;

		if (sscanf(entry->d_name, "cpu%u%n", &cpu, &len) == 1 &&
		    entry->d_name[len] == '\0' && cpu < MAX_CPUS)
			dirs.has[cpu] = true;
	}
	if (dir)
		closedir(dir);
	TEST_RES(is_equal(&dirs, &present), _ret);

	for (int cpu = 0; cpu < MAX_CPUS; cpu++) {
		char path[PATH_MAX], expected[PATH_MAX];

		if (!present.has[cpu])
			continue;

		snprintf(path, sizeof(path), "/sys/bus/cpu/devices/cpu%d", cpu);
		snprintf(expected, sizeof(expected), ROOT "/cpu%d", cpu);
		TEST_RES(resolves_to(path, expected), _ret);

		snprintf(path, sizeof(path), ROOT "/cpu%d/subsystem", cpu);
		TEST_RES(resolves_to(path, "/sys/bus/cpu"), _ret);
	}

	/* The root device belongs to no subsystem. */
	TEST_ERRNO(access(ROOT "/subsystem", F_OK), ENOENT);
	TEST_ERRNO(access("/sys/bus/cpu/devices/cpu", F_OK), ENOENT);
}
END_TEST()

FN_TEST(topology)
{
	for (int cpu = 0; cpu < MAX_CPUS; cpu++) {
		struct cpus thread, core, pkg, core_siblings, other, mid;
		int pkg_id, core_id;

		if (!present.has[cpu])
			continue;

		TEST_RES(read_topology_set(cpu, "thread_siblings", &thread),
			 _ret == 0 && thread.has[cpu]);
		TEST_RES(read_topology_set(cpu, "core_cpus", &core),
			 _ret == 0 && is_equal(&core, &thread));
		TEST_RES(read_topology_set(cpu, "package_cpus", &pkg),
			 _ret == 0 && is_subset(&thread, &pkg) &&
				 is_subset(&pkg, &present));
		TEST_RES(read_topology_set(cpu, "core_siblings",
					   &core_siblings),
			 _ret == 0 && is_equal(&core_siblings, &pkg));
		TEST_RES(is_read_only(topology_path(cpu, "thread_siblings")) &&
				 is_read_only(topology_path(
					 cpu, "package_cpus_list")) &&
				 is_read_only(topology_path(cpu, "core_id")),
			 _ret);

		if (access(topology_path(cpu, "cluster_cpus"), F_OK) == 0) {
			TEST_RES(read_topology_set(cpu, "cluster_cpus", &mid),
				 _ret == 0 && is_subset(&thread, &mid) &&
					 is_subset(&mid, &pkg));
			TEST_RES(read_topology_id(cpu, "cluster_id"),
				 _ret != INT_MIN);
		}
		if (access(topology_path(cpu, "die_cpus"), F_OK) == 0) {
			TEST_RES(read_topology_set(cpu, "die_cpus", &mid),
				 _ret == 0 && is_subset(&thread, &mid) &&
					 is_subset(&mid, &pkg));
			TEST_RES(read_topology_id(cpu, "die_id"),
				 _ret != INT_MIN);
		}

		pkg_id = TEST_RES(read_topology_id(cpu, "physical_package_id"),
				  _ret != INT_MIN);
		core_id = TEST_RES(read_topology_id(cpu, "core_id"),
				   _ret != INT_MIN);

		/* The relations are equivalences that agree with the IDs. */
		for (int i = 0; i < MAX_CPUS; i++) {
			if (!present.has[i] || i == cpu)
				continue;
			if (thread.has[i]) {
				TEST_RES(read_topology_set(i, "thread_siblings",
							   &other),
					 _ret == 0 &&
						 is_equal(&other, &thread));
				TEST_RES(read_topology_id(i, "core_id"),
					 _ret == core_id);
			}
			if (pkg.has[i]) {
				TEST_RES(read_topology_set(i, "package_cpus",
							   &other),
					 _ret == 0 && is_equal(&other, &pkg));
			}
			TEST_RES(read_topology_id(i, "physical_package_id"),
				 (_ret == pkg_id) == pkg.has[i]);
		}
	}
}
END_TEST()

#ifdef __x86_64__
/* Returns the value of `key` in the block of `processor` in `/proc/cpuinfo`. */
static int cpuinfo_field(const char *text, int processor, const char *key)
{
	char header[64];
	const char *block, *next, *line;
	size_t key_len = strlen(key);

	snprintf(header, sizeof(header), "processor\t: %d\n", processor);
	block = strstr(text, header);
	if (!block)
		return INT_MIN;
	next = strstr(block + 1, "processor\t:");
	for (line = block; line && (!next || line < next);) {
		if (strncmp(line, key, key_len) == 0 &&
		    (line[key_len] == '\t' || line[key_len] == ' ')) {
			const char *colon = strchr(line, ':');

			return colon ? atoi(colon + 1) : INT_MIN;
		}
		line = strchr(line, '\n');
		if (line)
			line++;
	}
	return INT_MIN;
}

FN_TEST(cpuinfo)
{
	static char text[1 << 20];
	int fd, len = 0;
	ssize_t n;

	fd = TEST_RES(open("/proc/cpuinfo", O_RDONLY), _ret >= 0);
	while (fd >= 0 &&
	       (n = read(fd, text + len, sizeof(text) - 1 - len)) > 0)
		len += n;
	if (fd >= 0)
		close(fd);
	text[len] = '\0';

	for (int cpu = 0; cpu < MAX_CPUS; cpu++) {
		struct cpus pkg, thread;
		int cores = 0;

		if (!online.has[cpu])
			continue;
		if (read_topology_set(cpu, "package_cpus", &pkg) < 0)
			continue;

		/* A core is counted at its first thread. */
		for (int i = 0; i < MAX_CPUS; i++) {
			if (!pkg.has[i] ||
			    read_topology_set(i, "thread_siblings", &thread) <
				    0)
				continue;
			for (int j = 0; j < MAX_CPUS; j++) {
				if (thread.has[j]) {
					cores += j == i;
					break;
				}
			}
		}

		TEST_RES(cpuinfo_field(text, cpu, "physical id"),
			 _ret == read_topology_id(cpu, "physical_package_id"));
		TEST_RES(cpuinfo_field(text, cpu, "core id"),
			 _ret == read_topology_id(cpu, "core_id"));
		TEST_RES(cpuinfo_field(text, cpu, "siblings"),
			 _ret == count_cpus(&pkg));
		TEST_RES(cpuinfo_field(text, cpu, "cpu cores"), _ret == cores);
	}
}
END_TEST()
#endif
