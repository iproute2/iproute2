/*
 * tc_util.c		Misc TC utility functions.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>

#include "utils.h"
#include "tc_util.h"

int get_qdisc_handle(__u32 *h, char *str)
{
	__u32 maj;
	char *p;

	maj = TC_H_UNSPEC;
	if (strcmp(str, "none") == 0)
		goto ok;
	maj = strtoul(str, &p, 16);
	if (p == str)
		return -1;
	maj <<= 16;
	if (*p != ':' && *p!=0)
		return -1;
ok:
	*h = maj;
	return 0;
}

int get_tc_classid(__u32 *h, char *str)
{
	__u32 maj, min;
	char *p;

	maj = TC_H_ROOT;
	if (strcmp(str, "root") == 0)
		goto ok;
	maj = TC_H_UNSPEC;
	if (strcmp(str, "none") == 0)
		goto ok;
	maj = strtoul(str, &p, 16);
	if (p == str) {
		maj = 0;
		if (*p != ':')
			return -1;
	}
	if (*p == ':') {
		maj <<= 16;
		str = p+1;
		min = strtoul(str, &p, 16);
		if (*p != 0)
			return -1;
		maj |= min;
	} else if (*p != 0)
		return -1;

ok:
	*h = maj;
	return 0;
}

int print_tc_classid(char *buf, int len, __u32 h)
{
	if (h == TC_H_ROOT)
		sprintf(buf, "root");
	else if (h == TC_H_UNSPEC)
		snprintf(buf, len, "none");
	else if (TC_H_MAJ(h) == 0)
		snprintf(buf, len, ":%x", TC_H_MIN(h));
	else if (TC_H_MIN(h) == 0)
		snprintf(buf, len, "%x:", TC_H_MAJ(h)>>16);
	else
		snprintf(buf, len, "%x:%x", TC_H_MAJ(h)>>16, TC_H_MIN(h));
	return 0;
}

char * sprint_tc_classid(__u32 h, char *buf)
{
	if (print_tc_classid(buf, SPRINT_BSIZE-1, h))
		strcpy(buf, "???");
	return buf;
}


int get_rate(unsigned *rate, char *str)
{
	char *p;
	double bps = strtod(str, &p);

	if (p == str)
		return -1;

	if (*p) {
		if (strcasecmp(p, "kbps") == 0)
			bps *= 1024;
		else if (strcasecmp(p, "mbps") == 0)
			bps *= 1024*1024;
		else if (strcasecmp(p, "mbit") == 0)
			bps *= 1024*1024/8;
		else if (strcasecmp(p, "kbit") == 0)
			bps *= 1024/8;
		else if (strcasecmp(p, "bps") != 0)
			return -1;
	} else
		bps /= 8;

	*rate = bps;
	return 0;
}

int get_rate_and_cell(unsigned *rate, int *cell_log, char *str)
{
	char * slash = strchr(str, '/');

	if (slash)
		*slash = 0;

	if (get_rate(rate, str))
		return -1;

	if (slash) {
		int cell;
		int i;

		if (get_integer(&cell, slash+1, 0))
			return -1;
		*slash = '/';

		for (i=0; i<32; i++) {
			if ((1<<i) == cell) {
				*cell_log = i;
				return 0;
			}
		}
		return -1;
	}
	return 0;
}


int print_rate(char *buf, int len, __u32 rate)
{
	double tmp = (double)rate*8;

	if (tmp >= 1024*1023 && fabs(1024*1024*rint(tmp/(1024*1024)) - tmp) < 1024)
		snprintf(buf, len, "%gMbit", rint(tmp/(1024*1024)));
	else if (tmp >= 1024-16 && fabs(1024*rint(tmp/1024) - tmp) < 16)
		snprintf(buf, len, "%gKbit", rint(tmp/1024));
	else
		snprintf(buf, len, "%ubps", rate);
	return 0;
}

char * sprint_rate(__u32 rate, char *buf)
{
	if (print_rate(buf, SPRINT_BSIZE-1, rate))
		strcpy(buf, "???");
	return buf;
}

int get_usecs(unsigned *usecs, char *str)
{
	double t;
	char *p;

	t = strtod(str, &p);
	if (p == str)
		return -1;

	if (*p) {
		if (strcasecmp(p, "s") == 0 || strcasecmp(p, "sec")==0 ||
		    strcasecmp(p, "secs")==0)
			t *= 1000000;
		else if (strcasecmp(p, "ms") == 0 || strcasecmp(p, "msec")==0 ||
			 strcasecmp(p, "msecs") == 0)
			t *= 1000;
		else if (strcasecmp(p, "us") == 0 || strcasecmp(p, "usec")==0 ||
			 strcasecmp(p, "usecs") == 0)
			t *= 1;
		else
			return -1;
	}

	*usecs = t;
	return 0;
}


int print_usecs(char *buf, int len, __u32 usec)
{
	double tmp = usec;

	if (tmp >= 1000000)
		snprintf(buf, len, "%.1fs", tmp/1000000);
	else if (tmp >= 1000)
		snprintf(buf, len, "%.1fms", tmp/1000);
	else
		snprintf(buf, len, "%uus", usec);
	return 0;
}

char * sprint_usecs(__u32 usecs, char *buf)
{
	if (print_usecs(buf, SPRINT_BSIZE-1, usecs))
		strcpy(buf, "???");
	return buf;
}

int get_size(unsigned *size, char *str)
{
	double sz;
	char *p;

	sz = strtod(str, &p);
	if (p == str)
		return -1;

	if (*p) {
		if (strcasecmp(p, "kb") == 0 || strcasecmp(p, "k")==0)
			sz *= 1024;
		else if (strcasecmp(p, "mb") == 0 || strcasecmp(p, "m")==0)
			sz *= 1024*1024;
		else if (strcasecmp(p, "mbit") == 0)
			sz *= 1024*1024/8;
		else if (strcasecmp(p, "kbit") == 0)
			sz *= 1024/8;
		else if (strcasecmp(p, "b") != 0)
			return -1;
	}

	*size = sz;
	return 0;
}

int get_size_and_cell(unsigned *size, int *cell_log, char *str)
{
	char * slash = strchr(str, '/');

	if (slash)
		*slash = 0;

	if (get_size(size, str))
		return -1;

	if (slash) {
		int cell;
		int i;

		if (get_integer(&cell, slash+1, 0))
			return -1;
		*slash = '/';

		for (i=0; i<32; i++) {
			if ((1<<i) == cell) {
				*cell_log = i;
				return 0;
			}
		}
		return -1;
	}
	return 0;
}

int print_size(char *buf, int len, __u32 sz)
{
	double tmp = sz;

	if (sz >= 1024*1024 && fabs(1024*1024*rint(tmp/(1024*1024)) - sz) < 1024)
		snprintf(buf, len, "%gMb", rint(tmp/(1024*1024)));
	else if (sz >= 1024 && fabs(1024*rint(tmp/1024) - sz) < 16)
		snprintf(buf, len, "%gKb", rint(tmp/1024));
	else
		snprintf(buf, len, "%ub", sz);
	return 0;
}

char * sprint_size(__u32 size, char *buf)
{
	if (print_size(buf, SPRINT_BSIZE-1, size))
		strcpy(buf, "???");
	return buf;
}

int print_qdisc_handle(char *buf, int len, __u32 h)
{
	snprintf(buf, len, "%x:", TC_H_MAJ(h)>>16);
	return 0;
}

char * sprint_qdisc_handle(__u32 h, char *buf)
{
	if (print_qdisc_handle(buf, SPRINT_BSIZE-1, h))
		strcpy(buf, "???");
	return buf;
}


