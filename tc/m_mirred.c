/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * m_egress.c		ingress/egress packet mirror/redir actions module
 *
 * Authors:  J Hadi Salim (hadi@cyberus.ca)
 *
 * TODO: Add Ingress support
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
#include "tc_common.h"
#include <linux/tc_act/tc_mirred.h>

static void
explain(void)
{
	fprintf(stderr,
		"Usage: mirred <DIRECTION> <ACTION> [index INDEX] <TARGET>\n"
		"where:\n"
		"\tDIRECTION := <ingress | egress>\n"
		"\tACTION := <mirror | redirect>\n"
		"\tINDEX  is the specific policy instance id\n"
		"\tTARGET := <BLOCK | DEVICE>\n"
		"\tDEVICE := dev DEVICENAME\n"
		"\tDEVICENAME is the devicename\n"
		"\tBLOCK := blockid BLOCKID\n"
		"\tBLOCKID := 32-bit unsigned block ID\n");
}

static void
usage(void)
{
	explain();
	exit(-1);
}

static const char *mirred_n2a(int action)
{
	switch (action) {
	case TCA_EGRESS_REDIR:
		return "Egress Redirect";
	case TCA_INGRESS_REDIR:
		return "Ingress Redirect";
	case TCA_EGRESS_MIRROR:
		return "Egress Mirror";
	case TCA_INGRESS_MIRROR:
		return "Ingress Mirror";
	default:
		return "unknown";
	}
}

static const char *mirred_direction(int action)
{
	switch (action) {
	case TCA_EGRESS_REDIR:
	case TCA_EGRESS_MIRROR:
		return "egress";
	case TCA_INGRESS_REDIR:
	case TCA_INGRESS_MIRROR:
		return "ingress";
	default:
		return "unknown";
	}
}

static const char *mirred_action(int action)
{
	switch (action) {
	case TCA_EGRESS_REDIR:
	case TCA_INGRESS_REDIR:
		return "redirect";
	case TCA_EGRESS_MIRROR:
	case TCA_INGRESS_MIRROR:
		return "mirror";
	default:
		return "unknown";
	}
}

static int
parse_direction(const struct action_util *a, int *argc_p, char ***argv_p,
		int tca_id, struct nlmsghdr *n)
{

	int argc = *argc_p;
	char **argv = *argv_p;
	int ok = 0, iok = 0, mirror = 0, redir = 0, ingress = 0, egress = 0;
	struct tc_mirred p = {};
	struct rtattr *tail;
	char d[IFNAMSIZ] = {};
	__u32 blockid = 0;

	while (argc > 0) {

		if (matches(*argv, "action") == 0) {
			NEXT_ARG();
			break;
		} else if (!egress && matches(*argv, "egress") == 0) {
			egress = 1;
			if (ingress) {
				fprintf(stderr,
					"Can't have both egress and ingress\n");
				return -1;
			}
			NEXT_ARG();
			ok++;
			continue;
		} else if (!ingress && matches(*argv, "ingress") == 0) {
			ingress = 1;
			if (egress) {
				fprintf(stderr,
					"Can't have both ingress and egress\n");
				return -1;
			}
			NEXT_ARG();
			ok++;
			continue;
		} else {

			if (matches(*argv, "index") == 0) {
				NEXT_ARG();
				if (get_u32(&p.index, *argv, 10)) {
					fprintf(stderr, "Illegal \"index\"\n");
					return -1;
				}
				iok++;
				if (!ok) {
					argc--;
					argv++;
					break;
				}
			} else if (!ok) {
				fprintf(stderr,
					"was expecting egress or ingress (%s)\n",
					*argv);
				break;

			} else if (!mirror && matches(*argv, "mirror") == 0) {
				mirror = 1;
				if (redir) {
					fprintf(stderr,
						"Can't have both mirror and redir\n");
					return -1;
				}
				p.eaction = egress ? TCA_EGRESS_MIRROR :
					TCA_INGRESS_MIRROR;
				p.action = TC_ACT_PIPE;
				ok++;
			} else if (!redir && matches(*argv, "redirect") == 0) {
				redir = 1;
				if (mirror) {
					fprintf(stderr,
						"Can't have both mirror and redir\n");
					return -1;
				}
				p.eaction = egress ? TCA_EGRESS_REDIR :
					TCA_INGRESS_REDIR;
				p.action = TC_ACT_STOLEN;
				ok++;
			} else if ((redir || mirror)) {
				if (strcmp(*argv, "blockid") == 0) {
					if (strlen(d)) {
						fprintf(stderr,
							"blockid and device are mutually exclusive.\n");
						return -1;
					}
					NEXT_ARG();
					if (get_u32(&blockid, *argv, 0) ||
					    !blockid) {
						fprintf(stderr,
							"invalid block ID");
						return -1;
					}
					argc--;
					argv++;
				}
				if (argc && matches(*argv, "dev") == 0) {
					if (blockid) {
						fprintf(stderr,
							"blockid and device are mutually exclusive.\n");
						return -1;
					}
					NEXT_ARG();
					if (strlen(d))
						duparg("dev", *argv);

					strncpy(d, *argv, sizeof(d)-1);
					argc--;
					argv++;
				}

				break;

			}
		}

		NEXT_ARG();
	}

	if (!ok && !iok)
		return -1;

	if (d[0])  {
		int idx;

		ll_init_map(&rth);

		idx = ll_name_to_index(d);
		if (!idx)
			return nodev(d);

		p.ifindex = idx;
	}


	if (p.eaction == TCA_EGRESS_MIRROR || p.eaction == TCA_INGRESS_MIRROR)
		parse_action_control_dflt(&argc, &argv, &p.action, false,
					  TC_ACT_PIPE);

	if (argc) {
		if (iok && matches(*argv, "index") == 0) {
			fprintf(stderr, "mirred: Illegal double index\n");
			return -1;
		}

		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&p.index, *argv, 10)) {
				fprintf(stderr,
					"mirred: Illegal \"index\"\n");
				return -1;
			}
			argc--;
			argv++;
		}
	}

	tail = addattr_nest(n, MAX_MSG, tca_id);
	addattr_l(n, MAX_MSG, TCA_MIRRED_PARMS, &p, sizeof(p));
	if (blockid)
		addattr32(n, MAX_MSG, TCA_MIRRED_BLOCKID, blockid);
	addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}


static int
parse_mirred(const struct action_util *a, int *argc_p, char ***argv_p,
	     int tca_id, struct nlmsghdr *n)
{

	int argc = *argc_p;
	char **argv = *argv_p;

	if (argc < 0) {
		fprintf(stderr, "mirred bad argument count %d\n", argc);
		return -1;
	}

	if (matches(*argv, "mirred") == 0) {
		NEXT_ARG();
	} else {
		fprintf(stderr, "mirred bad argument %s\n", *argv);
		return -1;
	}


	if (matches(*argv, "egress") == 0 || matches(*argv, "ingress") == 0 ||
	    matches(*argv, "index") == 0) {
		int ret = parse_direction(a, &argc, &argv, tca_id, n);

		if (ret == 0) {
			*argc_p = argc;
			*argv_p = argv;
			return 0;
		}

	} else if (matches(*argv, "help") == 0) {
		usage();
	} else {
		fprintf(stderr, "mirred option not supported %s\n", *argv);
	}

	return -1;

}

static int
print_mirred(const struct action_util *au, FILE *f, struct rtattr *arg)
{
	struct tc_mirred *p;
	struct rtattr *tb[TCA_MIRRED_MAX + 1];
	const char *dev;

	print_string(PRINT_ANY, "kind", "%s ", "mirred");
	if (arg == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_MIRRED_MAX, arg);

	if (tb[TCA_MIRRED_PARMS] == NULL) {
		fprintf(stderr, "Missing mirred parameters\n");
		return -1;
	}
	p = RTA_DATA(tb[TCA_MIRRED_PARMS]);

	dev = ll_index_to_name(p->ifindex);
	if (dev == 0) {
		fprintf(stderr, "Cannot find device %d\n", p->ifindex);
		return -1;
	}

	print_string(PRINT_FP, NULL, "(%s", mirred_n2a(p->eaction));
	print_string(PRINT_JSON, "mirred_action", NULL,
		     mirred_action(p->eaction));
	print_string(PRINT_JSON, "direction", NULL,
		     mirred_direction(p->eaction));
	if (tb[TCA_MIRRED_BLOCKID]) {
		const __u32 *blockid = RTA_DATA(tb[TCA_MIRRED_BLOCKID]);

		print_uint(PRINT_ANY, "to_blockid", " to blockid %u)",
			   *blockid);
	} else {
		print_string(PRINT_ANY, "to_dev", " to device %s)", dev);
	}

	print_action_control(" ", p->action, "");

	print_nl();
	print_uint(PRINT_ANY, "index", "\tindex %u", p->index);
	print_int(PRINT_ANY, "ref", " ref %d", p->refcnt);
	print_int(PRINT_ANY, "bind", " bind %d", p->bindcnt);

	if (show_stats) {
		if (tb[TCA_MIRRED_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[TCA_MIRRED_TM]);

			print_tm(tm);
		}
	}
	print_nl();
	return 0;
}

struct action_util mirred_action_util = {
	.id = "mirred",
	.parse_aopt = parse_mirred,
	.print_aopt = print_mirred,
};
