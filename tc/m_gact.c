/*
 * m_gact.c		generic actions module
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:  J Hadi Salim (hadi@cyberus.ca)
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
#include <linux/tc_act/tc_gact.h>

/* define to turn on probablity stuff */

#ifdef CONFIG_GACT_PROB
static const char *prob_n2a(int p)
{
	if (p == PGACT_NONE)
		return "none";
	if (p == PGACT_NETRAND)
		return "netrand";
	if (p == PGACT_DETERM)
		return "determ";
	return "none";
}
#endif

static void
explain(void)
{
#ifdef CONFIG_GACT_PROB
	fprintf(stderr, "Usage: ... gact <ACTION> [RAND] [INDEX]\n");
	fprintf(stderr,
		"Where: \tACTION := reclassify | drop | continue | pass | pipe |\n"
		"       \t          goto chain <CHAIN_INDEX> | jump <JUMP_COUNT>\n"
			"\tRAND := random <RANDTYPE> <ACTION> <VAL>\n"
			"\tRANDTYPE := netrand | determ\n"
			"\tVAL : = value not exceeding 10000\n"
			"\tJUMP_COUNT := Absolute jump from start of action list\n"
			"\tINDEX := index value used\n"
			"\n");
#else
	fprintf(stderr, "Usage: ... gact <ACTION> [INDEX]\n");
	fprintf(stderr,
		"Where: \tACTION := reclassify | drop | continue | pass | pipe |\n"
		"       \t          goto chain <CHAIN_INDEX> | jump <JUMP_COUNT>\n"
		"\tINDEX := index value used\n"
		"\tJUMP_COUNT := Absolute jump from start of action list\n"
		"\n");
#endif
}


static void
usage(void)
{
	explain();
	exit(-1);
}

static int
parse_gact(struct action_util *a, int *argc_p, char ***argv_p,
	   int tca_id, struct nlmsghdr *n)
{
	int argc = *argc_p;
	char **argv = *argv_p;
	struct tc_gact p = { 0 };
#ifdef CONFIG_GACT_PROB
	int rd = 0;
	struct tc_gact_p pp;
#endif
	struct rtattr *tail;

	if (argc < 0)
		return -1;


	if (matches(*argv, "gact") == 0) {
		argc--;
		argv++;
	} else if (parse_action_control(&argc, &argv, &p.action, false) == -1) {
		usage();	/* does not return */
	}

#ifdef CONFIG_GACT_PROB
	if (argc > 0) {
		if (matches(*argv, "random") == 0) {
			rd = 1;
			NEXT_ARG();
			if (matches(*argv, "netrand") == 0) {
				NEXT_ARG();
				pp.ptype = PGACT_NETRAND;
			} else if  (matches(*argv, "determ") == 0) {
				NEXT_ARG();
				pp.ptype = PGACT_DETERM;
			} else {
				fprintf(stderr, "Illegal \"random type\"\n");
				return -1;
			}

			if (parse_action_control(&argc, &argv,
						 &pp.paction, false) == -1)
				usage();
			if (get_u16(&pp.pval, *argv, 10)) {
				fprintf(stderr, "Illegal probability val 0x%x\n", pp.pval);
				return -1;
			}
			if (pp.pval > 10000) {
				fprintf(stderr, "Illegal probability val  0x%x\n", pp.pval);
				return -1;
			}
			argc--;
			argv++;
		} else if (matches(*argv, "help") == 0) {
				usage();
		}
	}
#endif

	if (argc > 0) {
		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&p.index, *argv, 10)) {
				fprintf(stderr, "Illegal \"index\"\n");
				return -1;
			}
			argc--;
			argv++;
		} else if (matches(*argv, "help") == 0) {
				usage();
		}
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, MAX_MSG, tca_id, NULL, 0);
	addattr_l(n, MAX_MSG, TCA_GACT_PARMS, &p, sizeof(p));
#ifdef CONFIG_GACT_PROB
	if (rd) {
		addattr_l(n, MAX_MSG, TCA_GACT_PROB, &pp, sizeof(pp));
	}
#endif
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int
print_gact(struct action_util *au, FILE * f, struct rtattr *arg)
{
#ifdef CONFIG_GACT_PROB
	struct tc_gact_p *pp = NULL;
	struct tc_gact_p pp_dummy;
#endif
	struct tc_gact *p = NULL;
	struct rtattr *tb[TCA_GACT_MAX + 1];

	if (arg == NULL)
		return -1;

	parse_rtattr_nested(tb, TCA_GACT_MAX, arg);

	if (tb[TCA_GACT_PARMS] == NULL) {
		fprintf(f, "[NULL gact parameters]");
		return -1;
	}
	p = RTA_DATA(tb[TCA_GACT_PARMS]);

	fprintf(f, "gact ");
	print_action_control(f, "action ", p->action, "");
#ifdef CONFIG_GACT_PROB
	if (tb[TCA_GACT_PROB] != NULL) {
		pp = RTA_DATA(tb[TCA_GACT_PROB]);
	} else {
		/* need to keep consistent output */
		memset(&pp_dummy, 0, sizeof(pp_dummy));
		pp = &pp_dummy;
	}
	fprintf(f, "\n\t random type %s", prob_n2a(pp->ptype));
	print_action_control(f, " ", pp->paction, " ");
	fprintf(f, "val %d", pp->pval);
#endif
	fprintf(f, "\n\t index %u ref %d bind %d", p->index, p->refcnt,
		p->bindcnt);
	if (show_stats) {
		if (tb[TCA_GACT_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[TCA_GACT_TM]);

			print_tm(f, tm);
		}
	}
	fprintf(f, "\n ");
	return 0;
}

struct action_util gact_action_util = {
	.id = "gact",
	.parse_aopt = parse_gact,
	.print_aopt = print_gact,
};
