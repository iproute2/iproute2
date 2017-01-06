/*
 * ipvrf.c	"ip vrf"
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	David Ahern <dsa@cumulusnetworks.com>
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <linux/bpf.h>
#include <linux/if.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"
#include "bpf_util.h"

#define CGRP_PROC_FILE  "/cgroup.procs"

static void usage(void)
{
	fprintf(stderr, "Usage: ip vrf exec [NAME] cmd ...\n");
	fprintf(stderr, "       ip vrf identify [PID]\n");
	fprintf(stderr, "       ip vrf pids [NAME]\n");

	exit(-1);
}

static int vrf_identify(pid_t pid, char *name, size_t len)
{
	char path[PATH_MAX];
	char buf[4096];
	char *vrf, *end;
	FILE *fp;

	snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
	fp = fopen(path, "r");
	if (!fp)
		return -1;

	memset(name, 0, len);

	while (fgets(buf, sizeof(buf), fp)) {
		vrf = strstr(buf, "::/vrf/");
		if (vrf) {
			vrf += 7;  /* skip past "::/vrf/" */
			end = strchr(vrf, '\n');
			if (end)
				*end = '\0';

			strncpy(name, vrf, len - 1);
			break;
		}
	}

	fclose(fp);

	return 0;
}

static int ipvrf_identify(int argc, char **argv)
{
	char vrf[32];
	int rc;
	unsigned int pid;

	if (argc < 1)
		pid = getpid();
	else if (argc > 1)
		invarg("Extra arguments specified\n", argv[1]);
	else if (get_unsigned(&pid, argv[0], 10))
		invarg("Invalid pid\n", argv[0]);

	rc = vrf_identify(pid, vrf, sizeof(vrf));
	if (!rc) {
		if (vrf[0] != '\0')
			printf("%s\n", vrf);
	} else {
		fprintf(stderr, "Failed to lookup vrf association: %s\n",
			strerror(errno));
	}

	return rc;
}

static int ipvrf_pids(int argc, char **argv)
{
	char path[PATH_MAX];
	char buf[4096];
	char *mnt, *vrf;
	int fd, rc = -1;
	ssize_t n;

	if (argc != 1) {
		fprintf(stderr, "Invalid arguments\n");
		return -1;
	}

	vrf = argv[0];

	mnt = find_cgroup2_mount();
	if (!mnt)
		return -1;

	snprintf(path, sizeof(path), "%s/vrf/%s%s", mnt, vrf, CGRP_PROC_FILE);
	free(mnt);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0; /* no cgroup file, nothing to show */

	while (1) {
		n = read(fd, buf, sizeof(buf) - 1);
		if (n < 0) {
			fprintf(stderr,
				"Failed to read cgroups file: %s\n",
				strerror(errno));
			break;
		} else if (n == 0) {
			rc = 0;
			break;
		}
		printf("%s", buf);
	}

	close(fd);

	return rc;
}

/* load BPF program to set sk_bound_dev_if for sockets */
static char bpf_log_buf[256*1024];

static int prog_load(int idx)
{
	struct bpf_insn prog[] = {
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
		BPF_MOV64_IMM(BPF_REG_3, idx),
		BPF_MOV64_IMM(BPF_REG_2,
			      offsetof(struct bpf_sock, bound_dev_if)),
		BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_3,
			    offsetof(struct bpf_sock, bound_dev_if)),
		BPF_MOV64_IMM(BPF_REG_0, 1), /* r0 = verdict */
		BPF_EXIT_INSN(),
	};

	return bpf_prog_load(BPF_PROG_TYPE_CGROUP_SOCK, prog, sizeof(prog),
			     "GPL", bpf_log_buf, sizeof(bpf_log_buf));
}

static int vrf_configure_cgroup(const char *path, int ifindex)
{
	int rc = -1, cg_fd, prog_fd = -1;

	cg_fd = open(path, O_DIRECTORY | O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr,
			"Failed to open cgroup path: '%s'\n",
			strerror(errno));
		goto out;
	}

	/*
	 * Load bpf program into kernel and attach to cgroup to affect
	 * socket creates
	 */
	prog_fd = prog_load(ifindex);
	if (prog_fd < 0) {
		fprintf(stderr, "Failed to load BPF prog: '%s'\n",
			strerror(errno));

		if (errno != EPERM) {
			fprintf(stderr,
				"Kernel compiled with CGROUP_BPF enabled?\n");
		}
		goto out;
	}

	if (bpf_prog_attach_fd(prog_fd, cg_fd, BPF_CGROUP_INET_SOCK_CREATE)) {
		fprintf(stderr, "Failed to attach prog to cgroup: '%s'\n",
			strerror(errno));
		goto out;
	}

	rc = 0;
out:
	close(cg_fd);
	close(prog_fd);

	return rc;
}

static int vrf_switch(const char *name)
{
	char path[PATH_MAX], *mnt, pid[16];
	int ifindex = 0;
	int rc = -1, len, fd = -1;

	if (strcmp(name, "default")) {
		ifindex = name_is_vrf(name);
		if (!ifindex) {
			fprintf(stderr, "Invalid VRF name\n");
			return -1;
		}
	}

	mnt = find_cgroup2_mount();
	if (!mnt)
		return -1;

	/* path to cgroup; make sure buffer has room to cat "/cgroup.procs"
	 * to the end of the path
	 */
	len = snprintf(path, sizeof(path) - sizeof(CGRP_PROC_FILE), "%s/vrf/%s",
		       mnt, ifindex ? name : "");
	if (len > sizeof(path) - sizeof(CGRP_PROC_FILE)) {
		fprintf(stderr, "Invalid path to cgroup2 mount\n");
		goto out;
	}

	if (make_path(path, 0755)) {
		fprintf(stderr, "Failed to setup vrf cgroup2 directory\n");
		goto out;
	}

	if (ifindex && vrf_configure_cgroup(path, ifindex))
		goto out;

	/*
	 * write pid to cgroup.procs making process part of cgroup
	 */
	strcat(path, CGRP_PROC_FILE);
	fd = open(path, O_RDWR | O_APPEND);
	if (fd < 0) {
		fprintf(stderr, "Failed to open cgroups.procs file: %s.\n",
			strerror(errno));
		goto out;
	}

	snprintf(pid, sizeof(pid), "%d", getpid());
	if (write(fd, pid, strlen(pid)) < 0) {
		fprintf(stderr, "Failed to join cgroup\n");
		goto out;
	}

	rc = 0;
out:
	free(mnt);
	close(fd);

	return rc;
}

static int ipvrf_exec(int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "No VRF name specified\n");
		return -1;
	}
	if (argc < 2) {
		fprintf(stderr, "No command specified\n");
		return -1;
	}

	if (vrf_switch(argv[0]))
		return -1;

	return -cmd_exec(argv[1], argv + 1, !!batch_mode);
}

/* reset VRF association of current process to default VRF;
 * used by netns_exec
 */
void vrf_reset(void)
{
	char vrf[32];

	if (vrf_identify(getpid(), vrf, sizeof(vrf)) ||
	    (vrf[0] == '\0'))
		return;

	vrf_switch("default");
}

int do_ipvrf(int argc, char **argv)
{
	if (argc == 0) {
		fprintf(stderr, "No command given. Try \"ip vrf help\".\n");
		exit(-1);
	}

	if (matches(*argv, "identify") == 0)
		return ipvrf_identify(argc-1, argv+1);

	if (matches(*argv, "pids") == 0)
		return ipvrf_pids(argc-1, argv+1);

	if (matches(*argv, "exec") == 0)
		return ipvrf_exec(argc-1, argv+1);

	if (matches(*argv, "help") == 0)
		usage();

	fprintf(stderr, "Command \"%s\" is unknown, try \"ip vrf help\".\n",
		*argv);

	exit(-1);
}
