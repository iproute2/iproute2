/*
 * q_rtlim.c		RTLIM.
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
	fprintf(stderr, 
		"Usage: ... rlim limit PACKETS rate KBPS [ overhead BYTES ]\n");
}

static void explain1(char *arg)
{
	fprintf(stderr, "Illegal \"%s\"\n", arg);
}


#define usage() return(-1)

static int rlim_parse_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{
	unsigned x;
	struct tc_rlim_qopt opt = { 
		.overhead = 24,		/* Ether IPG + Preamble + CRC */
	};
	struct rtattr *tail;

	while (argc > 0) {
		if (matches(*argv, "limit") == 0) {
			NEXT_ARG();
			if (opt.limit) {
				fprintf(stderr, "Double \"limit\" spec\n");
				return -1;
			}
			if (get_size(&opt.limit, *argv)) {
				explain1("limit");
				return -1;
			}
		} else if (strcmp(*argv, "rate") == 0) {
			NEXT_ARG();
			if (opt.rate) {
				fprintf(stderr, "Double \"rate\" spec\n");
				return -1;
			}

			if (get_rate(&x, *argv)) {
				explain1("rate");
				return -1;
			}
			opt.rate = x;
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

	if (opt.rate == 0) {
		fprintf(stderr, "\"rate\" is required.\n");
		return -1;
	}

	if (opt.limit == 0)
		opt.limit = 1000;

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
	addattr_l(n, 2024, TCA_RLIM_PARMS, &opt, sizeof(opt));
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;

	return 0;
}

static int rlim_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_RLIM_PARMS+1];
	struct tc_rlim_qopt *qopt;
	SPRINT_BUF(b1);
	SPRINT_BUF(b2);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_RLIM_PARMS, opt);
	if (tb[TCA_RLIM_PARMS] == NULL)
		return -1;

	qopt = RTA_DATA(tb[TCA_RLIM_PARMS]);
	if (RTA_PAYLOAD(tb[TCA_RLIM_PARMS])  < sizeof(*qopt))
		return -1;

	fprintf(f, "limit %s rate %s overhead %u", 
		sprint_size(qopt->limit, b1),
		sprint_rate(qopt->rate, b2),
		qopt->overhead);

	return 0;
}

struct qdisc_util rlim_qdisc_util = {
	.id		= "rlim",
	.parse_qopt	= rlim_parse_opt,
	.print_qopt	= rlim_print_opt,
};

