/*
 * m_police.c		Parse/print policing module options.
 *
 *		This program is free software; you can u32istribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 * FIXES:       19990619 - J Hadi Salim (hadi@cyberus.ca)
 *		simple addattr packaging fix.
 *		2002: J Hadi Salim - Add tc action extensions syntax
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"

static int act_parse_police(struct action_util *a, int *argc_p,
			    char ***argv_p, int tca_id, struct nlmsghdr *n);
static int print_police(struct action_util *a, FILE *f, struct rtattr *tb);

struct action_util police_action_util = {
	.id = "police",
	.parse_aopt = act_parse_police,
	.print_aopt = print_police,
};

static void usage(void)
{
	fprintf(stderr, "Usage: ... police rate BPS burst BYTES[/BYTES] [ mtu BYTES[/BYTES] ]\n");
	fprintf(stderr, "                [ peakrate BPS ] [ avrate BPS ] [ overhead BYTES ]\n");
	fprintf(stderr, "                [ linklayer TYPE ] [ CONTROL ]\n");

	fprintf(stderr, "Where: CONTROL := conform-exceed <EXCEEDACT>[/NOTEXCEEDACT]\n");
	fprintf(stderr, "                  Define how to handle packets which exceed (<EXCEEDACT>)\n");
	fprintf(stderr, "                  or conform (<NOTEXCEEDACT>) the configured bandwidth limit.\n");
	fprintf(stderr, "       EXCEEDACT/NOTEXCEEDACT := { pipe | ok | reclassify | drop | continue |\n");
	fprintf(stderr, "                                   goto chain <CHAIN_INDEX> }\n");
	exit(-1);
}

static void explain1(char *arg)
{
	fprintf(stderr, "Illegal \"%s\"\n", arg);
}

static int act_parse_police(struct action_util *a, int *argc_p, char ***argv_p,
			    int tca_id, struct nlmsghdr *n)
{
	int argc = *argc_p;
	char **argv = *argv_p;
	int res = -1;
	int ok = 0;
	struct tc_police p = { .action = TC_POLICE_RECLASSIFY };
	__u32 rtab[256];
	__u32 ptab[256];
	__u32 avrate = 0;
	int presult = 0;
	unsigned buffer = 0, mtu = 0, mpu = 0;
	unsigned short overhead = 0;
	unsigned int linklayer = LINKLAYER_ETHERNET; /* Assume ethernet */
	int Rcell_log =  -1, Pcell_log = -1;
	struct rtattr *tail;

	if (a) /* new way of doing things */
		NEXT_ARG();

	if (argc <= 0)
		return -1;

	while (argc > 0) {

		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&p.index, *argv, 10)) {
				fprintf(stderr, "Illegal \"index\"\n");
				return -1;
			}
		} else if (matches(*argv, "burst") == 0 ||
			strcmp(*argv, "buffer") == 0 ||
			strcmp(*argv, "maxburst") == 0) {
			NEXT_ARG();
			if (buffer) {
				fprintf(stderr, "Double \"buffer/burst\" spec\n");
				return -1;
			}
			if (get_size_and_cell(&buffer, &Rcell_log, *argv) < 0) {
				explain1("buffer");
				return -1;
			}
		} else if (strcmp(*argv, "mtu") == 0 ||
			   strcmp(*argv, "minburst") == 0) {
			NEXT_ARG();
			if (mtu) {
				fprintf(stderr, "Double \"mtu/minburst\" spec\n");
				return -1;
			}
			if (get_size_and_cell(&mtu, &Pcell_log, *argv) < 0) {
				explain1("mtu");
				return -1;
			}
		} else if (strcmp(*argv, "mpu") == 0) {
			NEXT_ARG();
			if (mpu) {
				fprintf(stderr, "Double \"mpu\" spec\n");
				return -1;
			}
			if (get_size(&mpu, *argv)) {
				explain1("mpu");
				return -1;
			}
		} else if (strcmp(*argv, "rate") == 0) {
			NEXT_ARG();
			if (p.rate.rate) {
				fprintf(stderr, "Double \"rate\" spec\n");
				return -1;
			}
			if (get_rate(&p.rate.rate, *argv)) {
				explain1("rate");
				return -1;
			}
		} else if (strcmp(*argv, "avrate") == 0) {
			NEXT_ARG();
			if (avrate) {
				fprintf(stderr, "Double \"avrate\" spec\n");
				return -1;
			}
			if (get_rate(&avrate, *argv)) {
				explain1("avrate");
				return -1;
			}
		} else if (matches(*argv, "peakrate") == 0) {
			NEXT_ARG();
			if (p.peakrate.rate) {
				fprintf(stderr, "Double \"peakrate\" spec\n");
				return -1;
			}
			if (get_rate(&p.peakrate.rate, *argv)) {
				explain1("peakrate");
				return -1;
			}
		} else if (matches(*argv, "reclassify") == 0 ||
			   matches(*argv, "drop") == 0 ||
			   matches(*argv, "shot") == 0 ||
			   matches(*argv, "continue") == 0 ||
			   matches(*argv, "pass") == 0 ||
			   matches(*argv, "ok") == 0 ||
			   matches(*argv, "pipe") == 0 ||
			   matches(*argv, "goto") == 0) {
			if (!parse_action_control(&argc, &argv, &p.action, false))
				goto action_ctrl_ok;
			return -1;
		} else if (strcmp(*argv, "conform-exceed") == 0) {
			NEXT_ARG();
			if (!parse_action_control_slash(&argc, &argv, &p.action,
							&presult, true))
				goto action_ctrl_ok;
			return -1;
		} else if (matches(*argv, "overhead") == 0) {
			NEXT_ARG();
			if (get_u16(&overhead, *argv, 10)) {
				explain1("overhead"); return -1;
			}
		} else if (matches(*argv, "linklayer") == 0) {
			NEXT_ARG();
			if (get_linklayer(&linklayer, *argv)) {
				explain1("linklayer"); return -1;
			}
		} else if (strcmp(*argv, "help") == 0) {
			usage();
		} else {
			break;
		}
		NEXT_ARG_FWD();
action_ctrl_ok:
		ok++;
	}

	if (!ok)
		return -1;

	if (p.rate.rate && avrate)
		return -1;

	/* Must at least do late binding, use TB or ewma policing */
	if (!p.rate.rate && !avrate && !p.index) {
		fprintf(stderr, "\"rate\" or \"avrate\" MUST be specified.\n");
		return -1;
	}

	/* When the TB policer is used, burst is required */
	if (p.rate.rate && !buffer && !avrate) {
		fprintf(stderr, "\"burst\" requires \"rate\".\n");
		return -1;
	}

	if (p.peakrate.rate) {
		if (!p.rate.rate) {
			fprintf(stderr, "\"peakrate\" requires \"rate\".\n");
			return -1;
		}
		if (!mtu) {
			fprintf(stderr, "\"mtu\" is required, if \"peakrate\" is requested.\n");
			return -1;
		}
	}

	if (p.rate.rate) {
		p.rate.mpu = mpu;
		p.rate.overhead = overhead;
		if (tc_calc_rtable(&p.rate, rtab, Rcell_log, mtu,
				   linklayer) < 0) {
			fprintf(stderr, "POLICE: failed to calculate rate table.\n");
			return -1;
		}
		p.burst = tc_calc_xmittime(p.rate.rate, buffer);
	}
	p.mtu = mtu;
	if (p.peakrate.rate) {
		p.peakrate.mpu = mpu;
		p.peakrate.overhead = overhead;
		if (tc_calc_rtable(&p.peakrate, ptab, Pcell_log, mtu,
				   linklayer) < 0) {
			fprintf(stderr, "POLICE: failed to calculate peak rate table.\n");
			return -1;
		}
	}

	tail = addattr_nest(n, MAX_MSG, tca_id);
	addattr_l(n, MAX_MSG, TCA_POLICE_TBF, &p, sizeof(p));
	if (p.rate.rate)
		addattr_l(n, MAX_MSG, TCA_POLICE_RATE, rtab, 1024);
	if (p.peakrate.rate)
		addattr_l(n, MAX_MSG, TCA_POLICE_PEAKRATE, ptab, 1024);
	if (avrate)
		addattr32(n, MAX_MSG, TCA_POLICE_AVRATE, avrate);
	if (presult)
		addattr32(n, MAX_MSG, TCA_POLICE_RESULT, presult);

	addattr_nest_end(n, tail);
	res = 0;

	*argc_p = argc;
	*argv_p = argv;
	return res;
}

int parse_police(int *argc_p, char ***argv_p, int tca_id, struct nlmsghdr *n)
{
	return act_parse_police(NULL, argc_p, argv_p, tca_id, n);
}

static int print_police(struct action_util *a, FILE *f, struct rtattr *arg)
{
	SPRINT_BUF(b1);
	SPRINT_BUF(b2);
	struct tc_police *p;
	struct rtattr *tb[TCA_POLICE_MAX+1];
	unsigned int buffer;
	unsigned int linklayer;

	if (arg == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_POLICE_MAX, arg);

	if (tb[TCA_POLICE_TBF] == NULL) {
		fprintf(f, "[NULL police tbf]");
		return 0;
	}
#ifndef STOOPID_8BYTE
	if (RTA_PAYLOAD(tb[TCA_POLICE_TBF])  < sizeof(*p)) {
		fprintf(f, "[truncated police tbf]");
		return -1;
	}
#endif
	p = RTA_DATA(tb[TCA_POLICE_TBF]);

	fprintf(f, " police 0x%x ", p->index);
	fprintf(f, "rate %s ", sprint_rate(p->rate.rate, b1));
	buffer = tc_calc_xmitsize(p->rate.rate, p->burst);
	fprintf(f, "burst %s ", sprint_size(buffer, b1));
	fprintf(f, "mtu %s ", sprint_size(p->mtu, b1));
	if (show_raw)
		fprintf(f, "[%08x] ", p->burst);

	if (p->peakrate.rate)
		fprintf(f, "peakrate %s ", sprint_rate(p->peakrate.rate, b1));

	if (tb[TCA_POLICE_AVRATE])
		fprintf(f, "avrate %s ",
			sprint_rate(rta_getattr_u32(tb[TCA_POLICE_AVRATE]),
				    b1));

	print_action_control(f, "action ", p->action, "");

	if (tb[TCA_POLICE_RESULT]) {
		__u32 action = rta_getattr_u32(tb[TCA_POLICE_RESULT]);

		print_action_control(f, "/", action, " ");
	} else
		fprintf(f, " ");

	fprintf(f, "overhead %ub ", p->rate.overhead);
	linklayer = (p->rate.linklayer & TC_LINKLAYER_MASK);
	if (linklayer > TC_LINKLAYER_ETHERNET || show_details)
		fprintf(f, "linklayer %s ", sprint_linklayer(linklayer, b2));
	fprintf(f, "\n\tref %d bind %d", p->refcnt, p->bindcnt);
	if (show_stats) {
		if (tb[TCA_POLICE_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[TCA_POLICE_TM]);

			print_tm(f, tm);
		}
	}
	fprintf(f, "\n");


	return 0;
}

int tc_print_police(FILE *f, struct rtattr *arg)
{
	return print_police(&police_action_util, f, arg);
}
