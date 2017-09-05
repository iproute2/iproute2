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
#include "bpf_util.h"

static const enum bpf_prog_type bpf_type = BPF_PROG_TYPE_SCHED_ACT;

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
	fprintf(stderr, "action (default \'%s\').\n", bpf_prog_to_default_section(bpf_type));
	fprintf(stderr, "\n");
	fprintf(stderr, "Where UDS_FILE points to a unix domain socket file in order\n");
	fprintf(stderr, "to hand off control of all created eBPF maps to an agent.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where optionally INDEX points to an existing action, or\n");
	fprintf(stderr, "explicitly specifies an action index upon creation.\n");
}

static void bpf_cbpf_cb(void *nl, const struct sock_filter *ops, int ops_len)
{
	addattr16(nl, MAX_MSG, TCA_ACT_BPF_OPS_LEN, ops_len);
	addattr_l(nl, MAX_MSG, TCA_ACT_BPF_OPS, ops,
		  ops_len * sizeof(struct sock_filter));
}

static void bpf_ebpf_cb(void *nl, int fd, const char *annotation)
{
	addattr32(nl, MAX_MSG, TCA_ACT_BPF_FD, fd);
	addattrstrz(nl, MAX_MSG, TCA_ACT_BPF_NAME, annotation);
}

static const struct bpf_cfg_ops bpf_cb_ops = {
	.cbpf_cb = bpf_cbpf_cb,
	.ebpf_cb = bpf_ebpf_cb,
};

static int bpf_parse_opt(struct action_util *a, int *ptr_argc, char ***ptr_argv,
			 int tca_id, struct nlmsghdr *n)
{
	const char *bpf_obj = NULL, *bpf_uds_name = NULL;
	struct tc_act_bpf parm = {};
	struct bpf_cfg_in cfg = {};
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
			cfg.argc = argc;
			cfg.argv = argv;

			if (bpf_parse_common(bpf_type, &cfg, &bpf_cb_ops, n))
				return -1;

			argc = cfg.argc;
			argv = cfg.argv;

			bpf_obj = cfg.object;
			bpf_uds_name = cfg.uds;
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

	parse_action_control_dflt(&argc, &argv, &parm.action,
				  false, TC_ACT_PIPE);

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
	int dump_ok = 0;

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

	if (tb[TCA_ACT_BPF_OPS] && tb[TCA_ACT_BPF_OPS_LEN]) {
		bpf_print_ops(f, tb[TCA_ACT_BPF_OPS],
			      rta_getattr_u16(tb[TCA_ACT_BPF_OPS_LEN]));
		fprintf(f, " ");
	}

	if (tb[TCA_ACT_BPF_ID])
		dump_ok = bpf_dump_prog_info(f, rta_getattr_u32(tb[TCA_ACT_BPF_ID]));
	if (!dump_ok && tb[TCA_ACT_BPF_TAG]) {
		SPRINT_BUF(b);

		fprintf(f, "tag %s ",
			hexstring_n2a(RTA_DATA(tb[TCA_ACT_BPF_TAG]),
				      RTA_PAYLOAD(tb[TCA_ACT_BPF_TAG]),
				      b, sizeof(b)));
	}

	print_action_control(f, "default-action ", parm->action, "\n");
	fprintf(f, "\tindex %u ref %d bind %d", parm->index, parm->refcnt,
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
