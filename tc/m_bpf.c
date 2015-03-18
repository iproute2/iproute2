/*
 * m_bpf.c	BFP based action module
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Jiri Pirko <jiri@resnulli.us>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <linux/tc_act/tc_bpf.h>

#include "utils.h"
#include "rt_names.h"
#include "tc_util.h"
#include "tc_bpf.h"

static void explain(void)
{
	fprintf(stderr, "Usage: ... bpf ...\n");
	fprintf(stderr, "\n");
	fprintf(stderr, " [inline]:     run bytecode BPF_BYTECODE\n");
	fprintf(stderr, " [from file]:  run bytecode-file FILE\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where BPF_BYTECODE := \'s,c t f k,c t f k,c t f k,...\'\n");
	fprintf(stderr, "      c,t,f,k and s are decimals; s denotes number of 4-tuples\n");
	fprintf(stderr, "Where FILE points to a file containing the BPF_BYTECODE string\n");
}

static void usage(void)
{
	explain();
	exit(-1);
}

static int parse_bpf(struct action_util *a, int *argc_p, char ***argv_p,
		     int tca_id, struct nlmsghdr *n)
{
	int argc = *argc_p;
	char **argv = *argv_p;
	struct rtattr *tail;
	struct tc_act_bpf parm = { 0 };
	struct sock_filter bpf_ops[BPF_MAXINSNS];
	__u16 bpf_len = 0;

	if (matches(*argv, "bpf") != 0)
		return -1;

	NEXT_ARG();

	while (argc > 0) {
		if (matches(*argv, "run") == 0) {
			bool from_file;
			int ret;

			NEXT_ARG();
			if (strcmp(*argv, "bytecode-file") == 0) {
				from_file = true;
			} else if (strcmp(*argv, "bytecode") == 0) {
				from_file = false;
			} else {
				fprintf(stderr, "unexpected \"%s\"\n", *argv);
				explain();
				return -1;
			}
			NEXT_ARG();
			ret = bpf_parse_ops(argc, argv, bpf_ops, from_file);
			if (ret < 0) {
				fprintf(stderr, "Illegal \"bytecode\"\n");
				return -1;
			}
			bpf_len = ret;
		} else if (matches(*argv, "help") == 0) {
			usage();
		} else {
			break;
		}
		argc--;
		argv++;
	}

	parm.action = TC_ACT_PIPE;
	if (argc) {
		if (matches(*argv, "reclassify") == 0) {
			parm.action = TC_ACT_RECLASSIFY;
			argc--;
			argv++;
		} else if (matches(*argv, "pipe") == 0) {
			parm.action = TC_ACT_PIPE;
			argc--;
			argv++;
		} else if (matches(*argv, "drop") == 0 ||
			   matches(*argv, "shot") == 0) {
			parm.action = TC_ACT_SHOT;
			argc--;
			argv++;
		} else if (matches(*argv, "continue") == 0) {
			parm.action = TC_ACT_UNSPEC;
			argc--;
			argv++;
		} else if (matches(*argv, "pass") == 0) {
			parm.action = TC_ACT_OK;
			argc--;
			argv++;
		}
	}

	if (argc) {
		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&parm.index, *argv, 10)) {
				fprintf(stderr, "bpf: Illegal \"index\"\n");
				return -1;
			}
			argc--;
			argv++;
		}
	}

	if (!bpf_len) {
		fprintf(stderr, "bpf: Bytecode needs to be passed\n");
		explain();
		return -1;
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, MAX_MSG, tca_id, NULL, 0);
	addattr_l(n, MAX_MSG, TCA_ACT_BPF_PARMS, &parm, sizeof(parm));
	addattr16(n, MAX_MSG, TCA_ACT_BPF_OPS_LEN, bpf_len);
	addattr_l(n, MAX_MSG, TCA_ACT_BPF_OPS, &bpf_ops,
		  bpf_len * sizeof(struct sock_filter));
	tail->rta_len = (char *)NLMSG_TAIL(n) - (char *)tail;

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int print_bpf(struct action_util *au, FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[TCA_ACT_BPF_MAX + 1];
	struct tc_act_bpf *parm;

	if (arg == NULL)
		return -1;

	parse_rtattr_nested(tb, TCA_ACT_BPF_MAX, arg);

	if (!tb[TCA_ACT_BPF_PARMS]) {
		fprintf(f, "[NULL bpf parameters]");
		return -1;
	}
	parm = RTA_DATA(tb[TCA_ACT_BPF_PARMS]);

	fprintf(f, " bpf ");

	if (tb[TCA_ACT_BPF_OPS] && tb[TCA_ACT_BPF_OPS_LEN])
		bpf_print_ops(f, tb[TCA_ACT_BPF_OPS],
			      rta_getattr_u16(tb[TCA_ACT_BPF_OPS_LEN]));

	fprintf(f, "\n\tindex %d ref %d bind %d", parm->index, parm->refcnt,
		parm->bindcnt);

	if (show_stats) {
		if (tb[TCA_ACT_BPF_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[TCA_ACT_BPF_TM]);
			print_tm(f, tm);
		}
	}

	fprintf(f, "\n ");

	return 0;
}

struct action_util bpf_action_util = {
	.id = "bpf",
	.parse_aopt = parse_bpf,
	.print_aopt = print_bpf,
};
