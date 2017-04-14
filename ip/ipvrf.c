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
#include <dirent.h>
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

/*
 * parse process based cgroup file looking for PATH/vrf/NAME where
 * NAME is the name of the vrf the process is associated with
 */
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
		/* want the controller-less cgroup */
		if (strstr(buf, "::/") == NULL)
			continue;

		vrf = strstr(buf, "/vrf/");
		if (vrf) {
			vrf += 5;  /* skip past "/vrf/" */
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

/* read PATH/vrf/NAME/cgroup.procs file */
static void read_cgroup_pids(const char *base_path, char *name)
{
	char path[PATH_MAX];
	char buf[4096];
	FILE *fp;

	if (snprintf(path, sizeof(path), "%s/vrf/%s%s",
		     base_path, name, CGRP_PROC_FILE) >= sizeof(path))
		return;

	fp = fopen(path, "r");
	if (!fp)
		return; /* no cgroup file, nothing to show */

	/* dump contents (pids) of cgroup.procs */
	while (fgets(buf, sizeof(buf), fp)) {
		char *nl, comm[32];

		nl = strchr(buf, '\n');
		if (nl)
			*nl = '\0';

		if (get_command_name(buf, comm, sizeof(comm)))
			strcpy(comm, "<terminated?>");

		printf("%5s  %s\n", buf, comm);
	}

	fclose(fp);
}

/* recurse path looking for PATH[/NETNS]/vrf/NAME */
static int recurse_dir(char *base_path, char *name, const char *netns)
{
	char path[PATH_MAX];
	struct dirent *de;
	struct stat fstat;
	int rc;
	DIR *d;

	d = opendir(base_path);
	if (!d)
		return -1;

	while ((de = readdir(d)) != NULL) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		if (!strcmp(de->d_name, "vrf")) {
			const char *pdir = strrchr(base_path, '/');

			/* found a 'vrf' directory. if it is for the given
			 * namespace then dump the cgroup pids
			 */
			if (*netns == '\0' ||
			    (pdir && !strcmp(pdir+1, netns)))
				read_cgroup_pids(base_path, name);

			continue;
		}

		/* is this a subdir that needs to be walked */
		if (snprintf(path, sizeof(path), "%s/%s",
			     base_path, de->d_name) >= sizeof(path))
			continue;

		if (lstat(path, &fstat) < 0)
			continue;

		if (S_ISDIR(fstat.st_mode)) {
			rc = recurse_dir(path, name, netns);
			if (rc != 0)
				goto out;
		}
	}

	rc = 0;
out:
	closedir(d);

	return rc;
}

static int ipvrf_get_netns(char *netns, int len)
{
	if (netns_identify_pid("self", netns, len-3)) {
		fprintf(stderr, "Failed to get name of network namespace: %s\n",
			strerror(errno));
		return -1;
	}

	if (*netns != '\0')
		strcat(netns, "-ns");

	return 0;
}

static int ipvrf_pids(int argc, char **argv)
{
	char *mnt, *vrf;
	char netns[256];
	int ret = -1;

	if (argc != 1) {
		fprintf(stderr, "Invalid arguments\n");
		return -1;
	}

	vrf = argv[0];
	if (!name_is_vrf(vrf)) {
		fprintf(stderr, "Invalid VRF name\n");
		return -1;
	}

	mnt = find_cgroup2_mount();
	if (!mnt)
		return -1;

	if (ipvrf_get_netns(netns, sizeof(netns)) < 0)
		goto out;

	ret = recurse_dir(mnt, vrf, netns);

out:
	free(mnt);

	return ret;
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

/* get base path for controller-less cgroup for a process.
 * path returned does not include /vrf/NAME if it exists
 */
static int vrf_path(char *vpath, size_t len)
{
	char path[PATH_MAX];
	char buf[4096];
	char *vrf;
	FILE *fp;

	snprintf(path, sizeof(path), "/proc/%d/cgroup", getpid());
	fp = fopen(path, "r");
	if (!fp)
		return -1;

	vpath[0] = '\0';

	while (fgets(buf, sizeof(buf), fp)) {
		char *start, *nl;

		start = strstr(buf, "::/");
		if (!start)
			continue;

		/* advance past '::' */
		start += 2;

		nl = strchr(start, '\n');
		if (nl)
			*nl = '\0';

		vrf = strstr(start, "/vrf");
		if (vrf)
			*vrf = '\0';

		strncpy(vpath, start, len - 1);
		vpath[len - 1] = '\0';

		/* if vrf path is just / then return nothing */
		if (!strcmp(vpath, "/"))
			vpath[0] = '\0';

		break;
	}

	fclose(fp);

	return 0;
}

static int vrf_switch(const char *name)
{
	char path[PATH_MAX], *mnt, pid[16];
	char vpath[PATH_MAX], netns[256];
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

	/* -1 on length to add '/' to the end */
	if (ipvrf_get_netns(netns, sizeof(netns) - 1) < 0)
		return -1;

	if (vrf_path(vpath, sizeof(vpath)) < 0) {
		fprintf(stderr, "Failed to get base cgroup path: %s\n",
			strerror(errno));
		return -1;
	}

	/* if path already ends in netns then don't add it again */
	if (*netns != '\0') {
		char *pdir = strrchr(vpath, '/');

		if (!pdir)
			pdir = vpath;
		else
			pdir++;

		if (strcmp(pdir, netns) == 0)
			*pdir = '\0';

		strcat(netns, "/");
	}

	/* path to cgroup; make sure buffer has room to cat "/cgroup.procs"
	 * to the end of the path
	 */
	len = snprintf(path, sizeof(path) - sizeof(CGRP_PROC_FILE),
		       "%s%s/%svrf/%s",
		       mnt, vpath, netns, ifindex ? name : "");
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
