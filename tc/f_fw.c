/*
 * f_fw.c		FW filter.
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

#include "utils.h"
#include "tc_util.h"

static void explain(void)
{
	fprintf(stderr, "Usage: ... fw [ classid CLASSID ] [ police POLICE_SPEC ]\n");
	fprintf(stderr, "       POLICE_SPEC := ... look at TBF\n");
	fprintf(stderr, "       CLASSID := X:Y\n");
}

#define usage() return(-1)

static int fw_parse_opt(struct filter_util *qu, char *handle, int argc, char **argv, struct nlmsghdr *n)
{
	struct tc_police tp;
	struct tcmsg *t = NLMSG_DATA(n);
	struct rtattr *tail;

	memset(&tp, 0, sizeof(tp));

	if (handle) {
		if (get_u32(&t->tcm_handle, handle, 0)) {
			fprintf(stderr, "Illegal \"handle\"\n");
			return -1;
		}
	}

	if (argc == 0)
		return 0;

	tail = (struct rtattr*)(((void*)n)+NLMSG_ALIGN(n->nlmsg_len));
	addattr_l(n, 4096, TCA_OPTIONS, NULL, 0);

	while (argc > 0) {
		if (matches(*argv, "classid") == 0 ||
		    matches(*argv, "flowid") == 0) {
			unsigned handle;
			NEXT_ARG();
			if (get_tc_classid(&handle, *argv)) {
				fprintf(stderr, "Illegal \"classid\"\n");
				return -1;
			}
			addattr_l(n, 4096, TCA_FW_CLASSID, &handle, 4);
		} else if (matches(*argv, "police") == 0) {
			NEXT_ARG();
			if (parse_police(&argc, &argv, TCA_FW_POLICE, n)) {
				fprintf(stderr, "Illegal \"police\"\n");
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}
	tail->rta_len = (((void*)n)+n->nlmsg_len) - (void*)tail;
	return 0;
}

static int fw_print_opt(struct filter_util *qu, FILE *f, struct rtattr *opt, __u32 handle)
{
	struct rtattr *tb[TCA_FW_MAX+1];

	if (opt == NULL)
		return 0;

	memset(tb, 0, sizeof(tb));
	if (opt)
		parse_rtattr(tb, TCA_FW_MAX, RTA_DATA(opt), RTA_PAYLOAD(opt));

	if (handle)
		fprintf(f, "handle 0x%x ", handle);

	if (tb[TCA_FW_CLASSID]) {
		SPRINT_BUF(b1);
		fprintf(f, "classid %s ", sprint_tc_classid(*(__u32*)RTA_DATA(tb[TCA_FW_CLASSID]), b1));
	}

	if (tb[TCA_FW_POLICE])
		tc_print_police(f, tb[TCA_FW_POLICE]);
	return 0;
}

struct filter_util fw_util = {
	NULL,
	"fw",
	fw_parse_opt,
	fw_print_opt,
};
