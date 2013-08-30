/*
 * q_tbf.c		TBF.
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
	fprintf(stderr, "Usage: ... tbf limit BYTES burst BYTES[/BYTES] rate KBPS [ mtu BYTES[/BYTES] ]\n");
	fprintf(stderr, "               [ peakrate KBPS ] [ latency TIME ] ");
	fprintf(stderr, "[ overhead BYTES ] [ linklayer TYPE ]\n");
}

static void explain1(const char *arg, const char *val)
{
	fprintf(stderr, "tbf: illegal value for \"%s\": \"%s\"\n", arg, val);
}


static int tbf_parse_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{
	int ok=0;
	struct tc_tbf_qopt opt;
	__u32 rtab[256];
	__u32 ptab[256];
	unsigned buffer=0, mtu=0, mpu=0, latency=0;
	int Rcell_log=-1, Pcell_log = -1;
	unsigned short overhead=0;
	unsigned int linklayer = LINKLAYER_ETHERNET; /* Assume ethernet */
	struct rtattr *tail;

	memset(&opt, 0, sizeof(opt));

	while (argc > 0) {
		if (matches(*argv, "limit") == 0) {
			NEXT_ARG();
			if (opt.limit) {
				fprintf(stderr, "tbf: duplicate \"limit\" specification\n");
				return -1;
			}
			if (latency) {
				fprintf(stderr, "tbf: specifying both \"latency\" and \"limit\" is not allowed\n");
				return -1;
			}
			if (get_size(&opt.limit, *argv)) {
				explain1("limit", *argv);
				return -1;
			}
			ok++;
		} else if (matches(*argv, "latency") == 0) {
			NEXT_ARG();
			if (latency) {
				fprintf(stderr, "tbf: duplicate \"latency\" specification\n");
				return -1;
			}
			if (opt.limit) {
				fprintf(stderr, "tbf: specifying both \"limit\" and \"/latency\" is not allowed\n");
				return -1;
			}
			if (get_time(&latency, *argv)) {
				explain1("latency", *argv);
				return -1;
			}
			ok++;
		} else if (matches(*argv, "burst") == 0 ||
			strcmp(*argv, "buffer") == 0 ||
			strcmp(*argv, "maxburst") == 0) {
			const char *parm_name = *argv;
			NEXT_ARG();
			if (buffer) {
				fprintf(stderr, "tbf: duplicate \"buffer/burst/maxburst\" specification\n");
				return -1;
			}
			if (get_size_and_cell(&buffer, &Rcell_log, *argv) < 0) {
				explain1(parm_name, *argv);
				return -1;
			}
			ok++;
		} else if (strcmp(*argv, "mtu") == 0 ||
			   strcmp(*argv, "minburst") == 0) {
			const char *parm_name = *argv;
			NEXT_ARG();
			if (mtu) {
				fprintf(stderr, "tbf: duplicate \"mtu/minburst\" specification\n");
				return -1;
			}
			if (get_size_and_cell(&mtu, &Pcell_log, *argv) < 0) {
				explain1(parm_name, *argv);
				return -1;
			}
			ok++;
		} else if (strcmp(*argv, "mpu") == 0) {
			NEXT_ARG();
			if (mpu) {
				fprintf(stderr, "tbf: duplicate \"mpu\" specification\n");
				return -1;
			}
			if (get_size(&mpu, *argv)) {
				explain1("mpu", *argv);
				return -1;
			}
			ok++;
		} else if (strcmp(*argv, "rate") == 0) {
			NEXT_ARG();
			if (opt.rate.rate) {
				fprintf(stderr, "tbf: duplicate \"rate\" specification\n");
				return -1;
			}
			if (get_rate(&opt.rate.rate, *argv)) {
				explain1("rate", *argv);
				return -1;
			}
			ok++;
		} else if (matches(*argv, "peakrate") == 0) {
			NEXT_ARG();
			if (opt.peakrate.rate) {
				fprintf(stderr, "tbf: duplicate \"peakrate\" specification\n");
				return -1;
			}
			if (get_rate(&opt.peakrate.rate, *argv)) {
				explain1("peakrate", *argv);
				return -1;
			}
			ok++;
		} else if (matches(*argv, "overhead") == 0) {
			NEXT_ARG();
			if (overhead) {
				fprintf(stderr, "tbf: duplicate \"overhead\" specification\n");
				return -1;
			}
			if (get_u16(&overhead, *argv, 10)) {
				explain1("overhead", *argv); return -1;
			}
		} else if (matches(*argv, "linklayer") == 0) {
			NEXT_ARG();
			if (get_linklayer(&linklayer, *argv)) {
				explain1("linklayer", *argv); return -1;
			}
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "tbf: unknown parameter \"%s\"\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

        int verdict = 0;

        /* Be nice to the user: try to emit all error messages in
         * one go rather than reveal one more problem when a
         * previous one has been fixed.
         */
	if (opt.rate.rate == 0) {
		fprintf(stderr, "tbf: the \"rate\" parameter is mandatory.\n");
		verdict = -1;
	}
	if (!buffer) {
		fprintf(stderr, "tbf: the \"burst\" parameter is mandatory.\n");
		verdict = -1;
	}
	if (opt.peakrate.rate) {
		if (!mtu) {
			fprintf(stderr, "tbf: when \"peakrate\" is specified, \"mtu\" must also be specified.\n");
			verdict = -1;
		}
	}

	if (opt.limit == 0 && latency == 0) {
		fprintf(stderr, "tbf: either \"limit\" or \"latency\" is required.\n");
		verdict = -1;
	}

        if (verdict != 0) {
                explain();
                return verdict;
        }

	if (opt.limit == 0) {
		double lim = opt.rate.rate*(double)latency/TIME_UNITS_PER_SEC + buffer;
		if (opt.peakrate.rate) {
			double lim2 = opt.peakrate.rate*(double)latency/TIME_UNITS_PER_SEC + mtu;
			if (lim2 < lim)
				lim = lim2;
		}
		opt.limit = lim;
	}

	opt.rate.mpu      = mpu;
	opt.rate.overhead = overhead;
	if (tc_calc_rtable(&opt.rate, rtab, Rcell_log, mtu, linklayer) < 0) {
		fprintf(stderr, "tbf: failed to calculate rate table.\n");
		return -1;
	}
	opt.buffer = tc_calc_xmittime(opt.rate.rate, buffer);

	if (opt.peakrate.rate) {
		opt.peakrate.mpu      = mpu;
		opt.peakrate.overhead = overhead;
		if (tc_calc_rtable(&opt.peakrate, ptab, Pcell_log, mtu, linklayer) < 0) {
			fprintf(stderr, "tbf: failed to calculate peak rate table.\n");
			return -1;
		}
		opt.mtu = tc_calc_xmittime(opt.peakrate.rate, mtu);
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
	addattr_l(n, 2024, TCA_TBF_PARMS, &opt, sizeof(opt));
	addattr_l(n, 3024, TCA_TBF_RTAB, rtab, 1024);
	if (opt.peakrate.rate)
		addattr_l(n, 4096, TCA_TBF_PTAB, ptab, 1024);
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	return 0;
}

static int tbf_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_TBF_PTAB+1];
	struct tc_tbf_qopt *qopt;
	unsigned int linklayer;
	double buffer, mtu;
	double latency;
	SPRINT_BUF(b1);
	SPRINT_BUF(b2);
	SPRINT_BUF(b3);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_TBF_PTAB, opt);

	if (tb[TCA_TBF_PARMS] == NULL)
		return -1;

	qopt = RTA_DATA(tb[TCA_TBF_PARMS]);
	if (RTA_PAYLOAD(tb[TCA_TBF_PARMS])  < sizeof(*qopt))
		return -1;
	fprintf(f, "rate %s ", sprint_rate(qopt->rate.rate, b1));
	buffer = tc_calc_xmitsize(qopt->rate.rate, qopt->buffer);
	if (show_details) {
		fprintf(f, "burst %s/%u mpu %s ", sprint_size(buffer, b1),
			1<<qopt->rate.cell_log, sprint_size(qopt->rate.mpu, b2));
	} else {
		fprintf(f, "burst %s ", sprint_size(buffer, b1));
	}
	if (show_raw)
		fprintf(f, "[%08x] ", qopt->buffer);
	if (qopt->peakrate.rate) {
		fprintf(f, "peakrate %s ", sprint_rate(qopt->peakrate.rate, b1));
		if (qopt->mtu || qopt->peakrate.mpu) {
			mtu = tc_calc_xmitsize(qopt->peakrate.rate, qopt->mtu);
			if (show_details) {
				fprintf(f, "mtu %s/%u mpu %s ", sprint_size(mtu, b1),
					1<<qopt->peakrate.cell_log, sprint_size(qopt->peakrate.mpu, b2));
			} else {
				fprintf(f, "minburst %s ", sprint_size(mtu, b1));
			}
			if (show_raw)
				fprintf(f, "[%08x] ", qopt->mtu);
		}
	}

	if (show_raw)
		fprintf(f, "limit %s ", sprint_size(qopt->limit, b1));

	latency = TIME_UNITS_PER_SEC*(qopt->limit/(double)qopt->rate.rate) - tc_core_tick2time(qopt->buffer);
	if (qopt->peakrate.rate) {
		double lat2 = TIME_UNITS_PER_SEC*(qopt->limit/(double)qopt->peakrate.rate) - tc_core_tick2time(qopt->mtu);
		if (lat2 > latency)
			latency = lat2;
	}
	fprintf(f, "lat %s ", sprint_time(latency, b1));

	if (qopt->rate.overhead) {
		fprintf(f, "overhead %d", qopt->rate.overhead);
	}
	linklayer = (qopt->rate.linklayer & TC_LINKLAYER_MASK);
	if (linklayer > TC_LINKLAYER_ETHERNET || show_details)
		fprintf(f, "linklayer %s ", sprint_linklayer(linklayer, b3));

	return 0;
}

struct qdisc_util tbf_qdisc_util = {
	.id		= "tbf",
	.parse_qopt	= tbf_parse_opt,
	.print_qopt	= tbf_print_opt,
};

