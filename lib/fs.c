/*
 * fs.c         filesystem APIs
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include "utils.h"

#define CGROUP2_FS_NAME "cgroup2"

/* if not already mounted cgroup2 is mounted here for iproute2's use */
#define MNT_CGRP2_PATH  "/var/run/cgroup2"

/* return mount path of first occurrence of given fstype */
static char *find_fs_mount(const char *fs_to_find)
{
	char path[4096];
	char fstype[128];    /* max length of any filesystem name */
	char *mnt = NULL;
	FILE *fp;

	fp = fopen("/proc/mounts", "r");
	if (!fp) {
		fprintf(stderr,
			"Failed to open mounts file: %s\n", strerror(errno));
		return NULL;
	}

	while (fscanf(fp, "%*s %4096s %127s %*s %*d %*d\n",
		      path, fstype) == 2) {
		if (strcmp(fstype, fs_to_find) == 0) {
			mnt = strdup(path);
			break;
		}
	}

	fclose(fp);

	return mnt;
}

/* caller needs to free string returned */
char *find_cgroup2_mount(void)
{
	char *mnt = find_fs_mount(CGROUP2_FS_NAME);

	if (mnt)
		return mnt;

	mnt = strdup(MNT_CGRP2_PATH);
	if (!mnt) {
		fprintf(stderr, "Failed to allocate memory for cgroup2 path\n");
		return NULL;

	}

	if (make_path(mnt, 0755)) {
		fprintf(stderr, "Failed to setup vrf cgroup2 directory\n");
		free(mnt);
		return NULL;
	}

	if (mount("none", mnt, CGROUP2_FS_NAME, 0, NULL)) {
		/* EBUSY means already mounted */
		if (errno != EBUSY) {
			fprintf(stderr,
				"Failed to mount cgroup2. Are CGROUPS enabled in your kernel?\n");
			free(mnt);
			return NULL;
		}
	}
	return mnt;
}

int make_path(const char *path, mode_t mode)
{
	char *dir, *delim;
	struct stat sbuf;
	int rc = -1;

	delim = dir = strdup(path);
	if (dir == NULL) {
		fprintf(stderr, "strdup failed copying path");
		return -1;
	}

	/* skip '/' -- it had better exist */
	if (*delim == '/')
		delim++;

	while (1) {
		delim = strchr(delim, '/');
		if (delim)
			*delim = '\0';

		if (stat(dir, &sbuf) != 0) {
			if (errno != ENOENT) {
				fprintf(stderr,
					"stat failed for %s: %s\n",
					dir, strerror(errno));
				goto out;
			}

			if (mkdir(dir, mode) != 0) {
				fprintf(stderr,
					"mkdir failed for %s: %s",
					dir, strerror(errno));
				goto out;
			}
		}

		if (delim == NULL)
			break;

		*delim = '/';
		delim++;
		if (*delim == '\0')
			break;
	}
	rc = 0;
out:
	free(dir);

	return rc;
}
