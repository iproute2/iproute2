/*
 * q_netem.c		NETEM.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Stephen Hemminger <shemminger@osdl.org>
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
	fprintf(stderr, "Usage: ... netem latency TIME  rate KBPS [ mtu BYTES ]\n");
	fprintf(stderr, "                 [ limit BYTES]\n");
}

static void explain1(const char *arg)
{
	fprintf(stderr, "Illegal \"%s\"\n", arg);
}

#define usage() return(-1)

static int netem_parse_opt(struct qdisc_util *qu, int argc, char **argv, 
			   struct nlmsghdr *n)
{
	struct tc_netem_qopt opt;
	unsigned mtu=1500, rate=0;
	int ok = 0;

	memset(&opt, 0, sizeof(opt));

	while (argc > 0) {
		if (matches(*argv, "limit") == 0) {
			NEXT_ARG();
			if (opt.limit || rate) {
				fprintf(stderr, "Double \"limit/rate\" spec\n");
				return -1;
			}
			if (get_size(&opt.limit, *argv)) {
				explain1("limit");
				return -1;
			}
			ok++;
		} else if (matches(*argv, "latency") == 0) {
			NEXT_ARG();
			if (get_usecs(&opt.latency, *argv)) {
				explain1("latency");
				return -1;
			}
			ok++;
		} else if (matches(*argv, "loss") == 0) {
			NEXT_ARG();
			if (get_percent(&opt.loss, *argv)) {
				explain1("loss");
				return -1;
			}
			ok++;
		} else if (matches(*argv, "gap") == 0) {
			char *p;
			NEXT_ARG();
			opt.gap = strtoul(*argv, &p, 0);
			if (p == *argv || *p) {
				explain1("gap");
				return -1;
			}
			ok++;
		} else if (matches(*argv, "rate") == 0) {
			NEXT_ARG();
			if (rate) {
				fprintf(stderr, "Double \"rate\" spec\n");
				return -1;
			}
			if (get_rate(&rate, *argv)) {
				explain1("rate");
				return -1;
			}
			ok++;
		} else if (strcmp(*argv, "mtu") == 0) {
			NEXT_ARG();
			if (get_size(&mtu, *argv)) {
				explain1("mtu");
				return -1;
			}
			ok++;
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

	if (!ok)
		return 0;

	if (!opt.limit && !rate) {
		fprintf(stderr, "Either \"limit\" or \"rate\" are required.\n");
		return -1;
	}
	
	/* Compute netem bandwith product as limit */
	if (opt.limit == 0) 
		opt.limit = ((double)rate * (double)opt.latency/1000000.);

	addattr_l(n, 1024, TCA_OPTIONS, &opt, sizeof(opt));
	return 0;
}

static int netem_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct tc_netem_qopt *qopt;
	SPRINT_BUF(b1);
	SPRINT_BUF(b2);

	if (opt == NULL)
		return 0;

	if (RTA_PAYLOAD(opt)  < sizeof(*qopt))
		return -1;

	qopt = RTA_DATA(opt);

	fprintf(f, "limit %s", sprint_size(qopt->limit, b1));
	if (qopt->latency)
		fprintf(f, " latency %s", 
			sprint_usecs(qopt->latency, b2));
	if (qopt->loss)
		fprintf(f, " loss %s",
			sprint_percent(qopt->loss, b1));
	if (qopt->gap)
		fprintf(f, " gap %lu", (unsigned long)qopt->gap);

	return 0;
}

static int netem_print_xstats(struct qdisc_util *qu, FILE *f, struct rtattr *xstats)
{
	return 0;
}

struct qdisc_util netem_util = {
	NULL,
	"netem",
	netem_parse_opt,
	netem_print_opt,
	netem_print_xstats,
};
