/*
 * m_bpf.c	BPF based action module
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Jiri Pirko <jiri@resnulli.us>
 *              Daniel Borkmann <daniel@iogearbox.net>
 */

#include <stdio.h>
#include <stdlib.h>

#include <linux/bpf.h>
#include <linux/tc_act/tc_bpf.h>

#include "utils.h"
#include "tc_util.h"
#include "tc_bpf.h"

static const enum bpf_prog_type bpf_type = BPF_PROG_TYPE_SCHED_ACT;

static const int nla_tbl[BPF_NLA_MAX] = {
	[BPF_NLA_OPS_LEN]	= TCA_ACT_BPF_OPS_LEN,
	[BPF_NLA_OPS]		= TCA_ACT_BPF_OPS,
	[BPF_NLA_FD]		= TCA_ACT_BPF_FD,
	[BPF_NLA_NAME]		= TCA_ACT_BPF_NAME,
};

static void explain(void)
{
	fprintf(stderr, "Usage: ... bpf ... [ index INDEX ]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "BPF use case:\n");
	fprintf(stderr, " bytecode BPF_BYTECODE\n");
	fprintf(stderr, " bytecode-file FILE\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "eBPF use case:\n");
	fprintf(stderr, " object-file FILE [ section ACT_NAME ] [ export UDS_FILE ]");
	fprintf(stderr, " [ verbose ]\n");
	fprintf(stderr, " object-pinned FILE\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where BPF_BYTECODE := \'s,c t f k,c t f k,c t f k,...\'\n");
	fprintf(stderr, "c,t,f,k and s are decimals; s denotes number of 4-tuples\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where FILE points to a file containing the BPF_BYTECODE string,\n");
	fprintf(stderr, "an ELF file containing eBPF map definitions and bytecode, or a\n");
	fprintf(stderr, "pinned eBPF program.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where ACT_NAME refers to the section name containing the\n");
	fprintf(stderr, "action (default \'%s\').\n", bpf_default_section(bpf_type));
	fprintf(stderr, "\n");
	fprintf(stderr, "Where UDS_FILE points to a unix domain socket file in order\n");
	fprintf(stderr, "to hand off control of all created eBPF maps to an agent.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where optionally INDEX points to an existing action, or\n");
	fprintf(stderr, "explicitly specifies an action index upon creation.\n");
}

static int bpf_parse_opt(struct action_util *a, int *ptr_argc, char ***ptr_argv,
			 int tca_id, struct nlmsghdr *n)
{
	const char *bpf_obj = NULL, *bpf_uds_name = NULL;
	struct tc_act_bpf parm;
	bool seen_run = false;
	struct rtattr *tail;
	int argc, ret = 0;
	char **argv;

	argv = *ptr_argv;
	argc = *ptr_argc;

	if (matches(*argv, "bpf") != 0)
		return -1;

	NEXT_ARG();

	tail = NLMSG_TAIL(n);
	addattr_l(n, MAX_MSG, tca_id, NULL, 0);

	while (argc > 0) {
		if (matches(*argv, "run") == 0) {
			NEXT_ARG();
opt_bpf:
			seen_run = true;
			if (bpf_parse_common(&argc, &argv, nla_tbl, bpf_type,
					     &bpf_obj, &bpf_uds_name, n)) {
				fprintf(stderr, "Failed to retrieve (e)BPF data!\n");
				return -1;
			}
		} else if (matches(*argv, "help") == 0) {
			explain();
			return -1;
		} else if (matches(*argv, "index") == 0) {
			break;
		} else {
			if (!seen_run)
				goto opt_bpf;
			break;
		}

		NEXT_ARG_FWD();
	}

	memset(&parm, 0, sizeof(parm));
	parm.action = TC_ACT_PIPE;

	if (argc) {
		if (matches(*argv, "reclassify") == 0) {
			parm.action = TC_ACT_RECLASSIFY;
			NEXT_ARG_FWD();
		} else if (matches(*argv, "pipe") == 0) {
			parm.action = TC_ACT_PIPE;
			NEXT_ARG_FWD();
		} else if (matches(*argv, "drop") == 0 ||
			   matches(*argv, "shot") == 0) {
			parm.action = TC_ACT_SHOT;
			NEXT_ARG_FWD();
		} else if (matches(*argv, "continue") == 0) {
			parm.action = TC_ACT_UNSPEC;
			NEXT_ARG_FWD();
		} else if (matches(*argv, "pass") == 0 ||
			   matches(*argv, "ok") == 0) {
			parm.action = TC_ACT_OK;
			NEXT_ARG_FWD();
		}
	}

	if (argc) {
		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&parm.index, *argv, 10)) {
				fprintf(stderr, "bpf: Illegal \"index\"\n");
				return -1;
			}

			NEXT_ARG_FWD();
		}
	}

	addattr_l(n, MAX_MSG, TCA_ACT_BPF_PARMS, &parm, sizeof(parm));
	tail->rta_len = (char *)NLMSG_TAIL(n) - (char *)tail;

	if (bpf_uds_name)
		ret = bpf_send_map_fds(bpf_uds_name, bpf_obj);

	*ptr_argc = argc;
	*ptr_argv = argv;

	return ret;
}

static int bpf_print_opt(struct action_util *au, FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[TCA_ACT_BPF_MAX + 1];
	struct tc_act_bpf *parm;
	SPRINT_BUF(action_buf);

	if (arg == NULL)
		return -1;

	parse_rtattr_nested(tb, TCA_ACT_BPF_MAX, arg);

	if (!tb[TCA_ACT_BPF_PARMS]) {
		fprintf(f, "[NULL bpf parameters]");
		return -1;
	}

	parm = RTA_DATA(tb[TCA_ACT_BPF_PARMS]);
	fprintf(f, "bpf ");

	if (tb[TCA_ACT_BPF_NAME])
		fprintf(f, "%s ", rta_getattr_str(tb[TCA_ACT_BPF_NAME]));
	else if (tb[TCA_ACT_BPF_FD])
		fprintf(f, "pfd %u ", rta_getattr_u32(tb[TCA_ACT_BPF_FD]));

	if (tb[TCA_ACT_BPF_OPS] && tb[TCA_ACT_BPF_OPS_LEN]) {
		bpf_print_ops(f, tb[TCA_ACT_BPF_OPS],
			      rta_getattr_u16(tb[TCA_ACT_BPF_OPS_LEN]));
		fprintf(f, " ");
	}

	fprintf(f, "default-action %s\n", action_n2a(parm->action, action_buf,
		sizeof(action_buf)));
	fprintf(f, "\tindex %d ref %d bind %d", parm->index, parm->refcnt,
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
	.id		= "bpf",
	.parse_aopt	= bpf_parse_opt,
	.print_aopt	= bpf_print_opt,
};
