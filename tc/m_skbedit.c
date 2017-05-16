/*
 * m_skbedit.c		SKB Editing module
 *
 * Copyright (c) 2008, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 *
 * Authors:	Alexander Duyck <alexander.h.duyck@intel.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "utils.h"
#include "tc_util.h"
#include <linux/tc_act/tc_skbedit.h>
#include <linux/if_packet.h>

static void explain(void)
{
	fprintf(stderr, "Usage: ... skbedit <[QM] [PM] [MM] [PT]>\n"
		"QM = queue_mapping QUEUE_MAPPING\n"
		"PM = priority PRIORITY\n"
		"MM = mark MARK\n"
		"PT = ptype PACKETYPE\n"
		"PACKETYPE = is one of:\n"
		"  host, otherhost, broadcast, multicast\n"
		"QUEUE_MAPPING = device transmit queue to use\n"
		"PRIORITY = classID to assign to priority field\n"
		"MARK = firewall mark to set\n");
}

static void
usage(void)
{
	explain();
	exit(-1);
}

static int
parse_skbedit(struct action_util *a, int *argc_p, char ***argv_p, int tca_id,
	      struct nlmsghdr *n)
{
	int argc = *argc_p;
	char **argv = *argv_p;
	int ok = 0;
	struct rtattr *tail;
	unsigned int tmp;
	__u16 queue_mapping, ptype;
	__u32 flags = 0, priority, mark;
	struct tc_skbedit sel = { 0 };

	if (matches(*argv, "skbedit") != 0)
		return -1;

	NEXT_ARG();

	while (argc > 0) {
		if (matches(*argv, "queue_mapping") == 0) {
			flags |= SKBEDIT_F_QUEUE_MAPPING;
			NEXT_ARG();
			if (get_unsigned(&tmp, *argv, 10) || tmp > 65535) {
				fprintf(stderr, "Illegal queue_mapping\n");
				return -1;
			}
			queue_mapping = tmp;
			ok++;
		} else if (matches(*argv, "priority") == 0) {
			flags |= SKBEDIT_F_PRIORITY;
			NEXT_ARG();
			if (get_tc_classid(&priority, *argv)) {
				fprintf(stderr, "Illegal priority\n");
				return -1;
			}
			ok++;
		} else if (matches(*argv, "mark") == 0) {
			flags |= SKBEDIT_F_MARK;
			NEXT_ARG();
			if (get_u32(&mark, *argv, 0)) {
				fprintf(stderr, "Illegal mark\n");
				return -1;
			}
			ok++;
		} else if (matches(*argv, "ptype") == 0) {

			NEXT_ARG();
			if (matches(*argv, "host") == 0) {
				ptype = PACKET_HOST;
			} else if (matches(*argv, "broadcast") == 0) {
				ptype = PACKET_BROADCAST;
			} else if (matches(*argv, "multicast") == 0) {
				ptype = PACKET_MULTICAST;
			} else if (matches(*argv, "otherhost") == 0) {
				ptype = PACKET_OTHERHOST;
			} else {
				fprintf(stderr, "Illegal ptype (%s)\n",
					*argv);
				return -1;
			}
			flags |= SKBEDIT_F_PTYPE;
			ok++;
		} else if (matches(*argv, "help") == 0) {
			usage();
		} else {
			break;
		}
		argc--;
		argv++;
	}

	parse_action_control_dflt(&argc, &argv, &sel.action,
				  false, TC_ACT_PIPE);

	if (argc) {
		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&sel.index, *argv, 10)) {
				fprintf(stderr, "Pedit: Illegal \"index\"\n");
				return -1;
			}
			argc--;
			argv++;
			ok++;
		}
	}

	if (!ok) {
		explain();
		return -1;
	}


	tail = NLMSG_TAIL(n);
	addattr_l(n, MAX_MSG, tca_id, NULL, 0);
	addattr_l(n, MAX_MSG, TCA_SKBEDIT_PARMS, &sel, sizeof(sel));
	if (flags & SKBEDIT_F_QUEUE_MAPPING)
		addattr_l(n, MAX_MSG, TCA_SKBEDIT_QUEUE_MAPPING,
			  &queue_mapping, sizeof(queue_mapping));
	if (flags & SKBEDIT_F_PRIORITY)
		addattr_l(n, MAX_MSG, TCA_SKBEDIT_PRIORITY,
			  &priority, sizeof(priority));
	if (flags & SKBEDIT_F_MARK)
		addattr_l(n, MAX_MSG, TCA_SKBEDIT_MARK,
			  &mark, sizeof(mark));
	if (flags & SKBEDIT_F_PTYPE)
		addattr_l(n, MAX_MSG, TCA_SKBEDIT_PTYPE,
			  &ptype, sizeof(ptype));
	tail->rta_len = (char *)NLMSG_TAIL(n) - (char *)tail;

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int print_skbedit(struct action_util *au, FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[TCA_SKBEDIT_MAX + 1];

	SPRINT_BUF(b1);
	__u32 *priority;
	__u32 *mark;
	__u16 *queue_mapping, *ptype;
	struct tc_skbedit *p = NULL;

	if (arg == NULL)
		return -1;

	parse_rtattr_nested(tb, TCA_SKBEDIT_MAX, arg);

	if (tb[TCA_SKBEDIT_PARMS] == NULL) {
		fprintf(f, "[NULL skbedit parameters]");
		return -1;
	}
	p = RTA_DATA(tb[TCA_SKBEDIT_PARMS]);

	fprintf(f, " skbedit");

	if (tb[TCA_SKBEDIT_QUEUE_MAPPING] != NULL) {
		queue_mapping = RTA_DATA(tb[TCA_SKBEDIT_QUEUE_MAPPING]);
		fprintf(f, " queue_mapping %u", *queue_mapping);
	}
	if (tb[TCA_SKBEDIT_PRIORITY] != NULL) {
		priority = RTA_DATA(tb[TCA_SKBEDIT_PRIORITY]);
		fprintf(f, " priority %s", sprint_tc_classid(*priority, b1));
	}
	if (tb[TCA_SKBEDIT_MARK] != NULL) {
		mark = RTA_DATA(tb[TCA_SKBEDIT_MARK]);
		fprintf(f, " mark %d", *mark);
	}
	if (tb[TCA_SKBEDIT_PTYPE] != NULL) {
		ptype = RTA_DATA(tb[TCA_SKBEDIT_PTYPE]);
		if (*ptype == PACKET_HOST)
			fprintf(f, " ptype host");
		else if (*ptype == PACKET_BROADCAST)
			fprintf(f, " ptype broadcast");
		else if (*ptype == PACKET_MULTICAST)
			fprintf(f, " ptype multicast");
		else if (*ptype == PACKET_OTHERHOST)
			fprintf(f, " ptype otherhost");
		else
			fprintf(f, " ptype %d", *ptype);
	}

	print_action_control(f, " ", p->action, "");

	fprintf(f, "\n\t index %u ref %d bind %d",
		p->index, p->refcnt, p->bindcnt);

	if (show_stats) {
		if (tb[TCA_SKBEDIT_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[TCA_SKBEDIT_TM]);

			print_tm(f, tm);
		}
	}

	fprintf(f, "\n ");

	return 0;
}

struct action_util skbedit_action_util = {
	.id = "skbedit",
	.parse_aopt = parse_skbedit,
	.print_aopt = print_skbedit,
};
