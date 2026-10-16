#define _GNU_SOURCE
// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>

#include "bio_merge.bpf.skel.h"

#define KSFT_PASS 0
#define KSFT_FAIL 1
#define KSFT_SKIP 4

static const char *const configfs_path = "/sys/kernel/config";
static const char *const nullb_dir = "/sys/kernel/config/nullb/iosched_ext_bio_merge";
static char dev_path[64];
static int cgroup_fd = -1;
static volatile sig_atomic_t timed_out;

static void handle_alarm(int signal)
{
	timed_out = 1;
}

static int write_file(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t len;

	if (fd < 0)
		return -errno;

	len = write(fd, value, strlen(value));
	close(fd);

	return len < 0 ? -errno : 0;
}

static int read_file(const char *path, char *buf, size_t size)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t len;

	if (fd < 0)
		return -errno;

	len = read(fd, buf, size - 1);
	close(fd);
	if (len < 0)
		return -errno;
	buf[len] = '\0';
	return 0;
}

static int ensure_configfs(void)
{
	struct stat st;

	if (!stat(configfs_path, &st))
		return 0;
	if (errno != ENOENT)
		return -errno;
	if (mkdir(configfs_path, 0755) && errno != EEXIST)
		return -errno;
	if (mount("configfs", configfs_path, "configfs", 0, NULL) && errno != EBUSY)
		return -errno;

	return 0;
}

static int setup_nullb(void)
{
	char path[128];
	char buf[256];
	int major, minor;
	dev_t dev;

	if (system("modprobe null_blk nr_devices=0 queue_mode=2 no_sched=0 2>/dev/null"))
		return -ENODEV;
	if (ensure_configfs())
		return -ENODEV;
	if (mkdir(nullb_dir, 0755) && errno != EEXIST)
		return -errno;

	snprintf(path, sizeof(path), "%s/queue_mode", nullb_dir);
	if (write_file(path, "2"))
		return -errno;
	snprintf(path, sizeof(path), "%s/submit_queues", nullb_dir);
	if (write_file(path, "1"))
		return -errno;
	snprintf(path, sizeof(path), "%s/hw_queue_depth", nullb_dir);
	if (write_file(path, "64"))
		return -errno;
	snprintf(path, sizeof(path), "%s/memory_backed", nullb_dir);
	if (write_file(path, "1"))
		return -errno;
	snprintf(path, sizeof(path), "%s/mbps", nullb_dir);
	if (write_file(path, "1"))
		return -errno;
	snprintf(path, sizeof(path), "%s/power", nullb_dir);
	if (write_file(path, "1"))
		return -errno;

	snprintf(path, sizeof(path), "%s/index", nullb_dir);
	if (read_file(path, buf, sizeof(buf)))
		return -errno;
	buf[strcspn(buf, "\n")] = '\0';
	if (strlen(buf) > 8)
		return -EINVAL;
	/*
	 * Newer kernels name configfs-created nullb devices after the config
	 * directory; older ones use nullb<index>.  Prefer whichever exists.
	 */
	snprintf(dev_path, sizeof(dev_path), "/dev/nullb%s", buf);
	snprintf(path, sizeof(path), "/sys/block/nullb%s/dev", buf);
	if (access(path, R_OK)) {
		snprintf(dev_path, sizeof(dev_path), "/dev/%s",
			 strrchr(nullb_dir, '/') + 1);
		snprintf(path, sizeof(path), "/sys/block/%s/dev",
			 strrchr(nullb_dir, '/') + 1);
	}

	if (access(dev_path, R_OK | W_OK)) {
		if (read_file(path, buf, sizeof(buf)))
			return -errno;
		if (sscanf(buf, "%d:%d", &major, &minor) != 2)
			return -EINVAL;
		dev = makedev(major, minor);
		if (mknod(dev_path, S_IFBLK | 0600, dev) && errno != EEXIST)
			return -errno;
	}

	snprintf(path, sizeof(path), "/sys/block/%s/queue/scheduler", strrchr(dev_path, '/') + 1);
	if (write_file(path, "scx_io"))
		return -errno;

	return 0;
}

static void cleanup_nullb(void)
{
	char path[128];

	if (!dev_path[0])
		return;
	snprintf(path, sizeof(path), "%s/power", nullb_dir);
	write_file(path, "0");
	rmdir(nullb_dir);
}

static int attach_policy(struct bio_merge *skel)
{
	/* Mirror of struct iosched_ext_ops from block/iosched_ext.h as
	 * typed by the generated skeleton (function members surface as
	 * bpf_program pointers, the name array as __unsupported_XX).
	 */
	__typeof__(*skel->struct_ops.bio_merge_ops) value = {};
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	union bpf_attr attr = {};
	int map_fd, fd, err;
	void *buf;

	value.insert_request = (void *)(long)bpf_program__fd(skel->progs.insert_request_reject);
	value.evacuate = (void *)(long)bpf_program__fd(skel->progs.evacuate_empty);
	value.bio_merge = (void *)(long)bpf_program__fd(skel->progs.bio_merge_true);
	strcpy((char *)&value.__unsupported_23, "bm_true");

	map_fd = bpf_map__fd(skel->maps.bio_merge_ops);
	if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len))
		return -errno;
	buf = calloc(1, info.value_size);
	if (!buf)
		return -ENOMEM;
	/* struct bpf_struct_ops_value places data[] on a cacheline boundary:
	 * past the bpf_struct_ops_common_value header padded to 64 bytes
	 * (see bits_offset=512 for 'data' in vmlinux BTF)
	 */
	memcpy(buf + 64, &value, sizeof(value));

	/* Bring the map to BPF_STRUCT_OPS_STATE_READY before linking. */
	err = bpf_map_update_elem(map_fd, &(int){0}, buf, 0);
	free(buf);
	if (err)
		return -errno;

	cgroup_fd = open("/sys/fs/cgroup", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (cgroup_fd < 0)
		return -errno;

	/* prog_fd and map_fd alias each other in the BPF_LINK_CREATE uapi. */
	attr.link_create.prog_fd = map_fd;
	attr.link_create.target_fd = cgroup_fd;
	attr.link_create.attach_type = BPF_STRUCT_OPS;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));

	return fd < 0 ? -errno : fd;
}

static int run_io(void)
{
	struct sigaction action = { .sa_handler = handle_alarm };
	char *data;
	int fd;
	int ret = 0;

	if (posix_memalign((void **)&data, 4096, 8192))
		return -ENOMEM;
	memset(data, 0x5a, 8192);

	sigaction(SIGALRM, &action, NULL);
	alarm(10);
	fd = open(dev_path, O_WRONLY | O_DIRECT | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;
		goto out_free;
	}

	if (pwrite(fd, data, 4096, 0) != 4096) {
		ret = timed_out ? -ETIMEDOUT : -errno;
		goto out_close;
	}
	if (pwrite(fd, data + 4096, 4096, 4096) != 4096) {
		ret = timed_out ? -ETIMEDOUT : -errno;
		goto out_close;
	}
	if (fsync(fd)) {
		ret = timed_out ? -ETIMEDOUT : -errno;
	}
out_close:
	alarm(0);
	close(fd);
out_free:
	free(data);
	return ret;
}

int main(void)
{
	struct bio_merge *skel;
	int link_fd = -1;
	int err, ret = KSFT_FAIL;

	if (geteuid()) {
		printf("1..0 # SKIP requires root\n");
		return KSFT_SKIP;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	err = setup_nullb();
	if (err) {
		printf("1..0 # SKIP null_blk/scx_io setup failed: %s\n", strerror(-err));
		return KSFT_SKIP;
	}

	skel = bio_merge__open_and_load();
	if (!skel) {
		printf("not ok 1 open/load BPF policy\n");
		goto out_nullb;
	}

	link_fd = attach_policy(skel);
	if (link_fd < 0) {
		printf("not ok 1 attach BPF policy: %s\n", strerror(-link_fd));
		goto out_skel;
	}

	err = run_io();
	if (err) {
		printf("not ok 1 merged I/O completed: %s\n", strerror(-err));
		goto out_link;
	}

	if (!skel->bss->bio_merge_calls) {
		printf("not ok 1 bio_merge hook was not exercised\n");
		goto out_link;
	}

	printf("ok 1 bio_merge true does not drop unmerged bio\n");
	ret = KSFT_PASS;

out_link:
	close(link_fd);
out_skel:
	bio_merge__destroy(skel);
out_nullb:
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	cleanup_nullb();
	return ret;
}
