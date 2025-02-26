/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * iplink_netkit.c netkit device management
 *
 * Authors:        Daniel Borkmann <daniel@iogearbox.net>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_link.h>

#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"

static const char * const netkit_mode_strings[] = {
	[NETKIT_L2]		= "l2",
	[NETKIT_L3]		= "l3",
};

static const char * const netkit_policy_strings[] = {
	[NETKIT_PASS]		= "forward",
	[NETKIT_DROP]		= "blackhole",
};

static const char * const netkit_scrub_strings[] = {
	[NETKIT_SCRUB_NONE]	= "none",
	[NETKIT_SCRUB_DEFAULT]	= "default",
};

static void explain(struct link_util *lu, FILE *f)
{
	fprintf(f,
		"Usage: ... %s [ mode MODE ] [ POLICY ] [ scrub SCRUB ] [ peer [ POLICY <options> ] ]\n"
		"\n"
		"MODE: l3 | l2\n"
		"POLICY: forward | blackhole\n"
		"SCRUB: default | none\n"
		"(first values are the defaults if nothing is specified)\n"
		"\n"
		"To get <options> type 'ip link add help'.\n",
		lu->id);
}

static int netkit_parse_opt(struct link_util *lu, int argc, char **argv,
			    struct nlmsghdr *n)
{
	__u32 ifi_flags, ifi_change, ifi_index;
	struct ifinfomsg *ifm, *peer_ifm;
	static bool seen_mode, seen_peer;
	static struct rtattr *data;
	int err;

	ifm = NLMSG_DATA(n);
	ifi_flags = ifm->ifi_flags;
	ifi_change = ifm->ifi_change;
	ifi_index = ifm->ifi_index;
	ifm->ifi_flags = 0;
	ifm->ifi_change = 0;
	ifm->ifi_index = 0;
	while (argc > 0) {
		if (strcmp(*argv, "mode") == 0) {
			__u32 mode = 0;

			NEXT_ARG();
			if (seen_mode)
				duparg("mode", *argv);
			seen_mode = true;

			if (strcmp(*argv, "l3") == 0) {
				mode = NETKIT_L3;
			} else if (strcmp(*argv, "l2") == 0) {
				mode = NETKIT_L2;
			} else {
				fprintf(stderr, "Error: argument of \"mode\" must be either \"l3\" or \"l2\"\n");
				return -1;
			}
			addattr32(n, 1024, IFLA_NETKIT_MODE, mode);
		} else if (strcmp(*argv, "forward") == 0 ||
			   strcmp(*argv, "blackhole") == 0) {
			int attr_name = seen_peer ?
					IFLA_NETKIT_PEER_POLICY :
					IFLA_NETKIT_POLICY;
			__u32 policy = 0;

			if (strcmp(*argv, "forward") == 0) {
				policy = NETKIT_PASS;
			} else if (strcmp(*argv, "blackhole") == 0) {
				policy = NETKIT_DROP;
			} else {
				fprintf(stderr, "Error: policy must be either \"forward\" or \"blackhole\"\n");
				return -1;
			}
			addattr32(n, 1024, attr_name, policy);
		} else if (strcmp(*argv, "peer") == 0) {
			if (seen_peer)
				duparg("peer", *(argv + 1));
			seen_peer = true;
		} else if (strcmp(*argv, "scrub") == 0) {
			int attr_name = seen_peer ?
					IFLA_NETKIT_PEER_SCRUB :
					IFLA_NETKIT_SCRUB;
			enum netkit_scrub scrub;

			NEXT_ARG();

			if (strcmp(*argv, "none") == 0) {
				scrub = NETKIT_SCRUB_NONE;
			} else if (strcmp(*argv, "default") == 0) {
				scrub = NETKIT_SCRUB_DEFAULT;
			} else {
				fprintf(stderr, "Error: scrub must be either \"none\" or \"default\"\n");
				return -1;
			}
			addattr32(n, 1024, attr_name, scrub);
		} else {
			char *type = NULL;

			if (seen_peer) {
				data = addattr_nest(n, 1024, IFLA_NETKIT_PEER_INFO);
				n->nlmsg_len += sizeof(struct ifinfomsg);
				err = iplink_parse(argc, argv, (struct iplink_req *)n, &type);
				if (err < 0)
					return err;
				if (type)
					duparg("type", argv[err]);
				goto out_ok;
			}
			fprintf(stderr, "%s: unknown option \"%s\"?\n",
				lu->id, *argv);
			explain(lu, stderr);
			return -1;
		}
		argc--;
		argv++;
	}
out_ok:
	if (data) {
		peer_ifm = RTA_DATA(data);
		peer_ifm->ifi_index = ifm->ifi_index;
		peer_ifm->ifi_flags = ifm->ifi_flags;
		peer_ifm->ifi_change = ifm->ifi_change;
		addattr_nest_end(n, data);
	}
	ifm->ifi_flags = ifi_flags;
	ifm->ifi_change = ifi_change;
	ifm->ifi_index = ifi_index;
	return 0;
}

static const char *netkit_print_policy(__u32 policy)
{
	const char *inv = "UNKNOWN";

	if (policy >= ARRAY_SIZE(netkit_policy_strings))
		return inv;
	return netkit_policy_strings[policy] ? : inv;
}

static const char *netkit_print_mode(__u32 mode)
{
	const char *inv = "UNKNOWN";

	if (mode >= ARRAY_SIZE(netkit_mode_strings))
		return inv;
	return netkit_mode_strings[mode] ? : inv;
}

static const char *netkit_print_scrub(enum netkit_scrub scrub)
{
	const char *inv = "UNKNOWN";

	if (scrub >= ARRAY_SIZE(netkit_scrub_strings))
		return inv;
	return netkit_scrub_strings[scrub] ? : inv;
}

static void netkit_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	if (!tb)
		return;
	if (tb[IFLA_NETKIT_MODE]) {
		__u32 mode = rta_getattr_u32(tb[IFLA_NETKIT_MODE]);

		print_string(PRINT_ANY, "mode", "mode %s ",
			     netkit_print_mode(mode));
	}
	if (tb[IFLA_NETKIT_PRIMARY]) {
		__u8 primary = rta_getattr_u8(tb[IFLA_NETKIT_PRIMARY]);

		print_string(PRINT_ANY, "type", "type %s ",
			     primary ? "primary" : "peer");
	}
	if (tb[IFLA_NETKIT_POLICY]) {
		__u32 policy = rta_getattr_u32(tb[IFLA_NETKIT_POLICY]);

		print_string(PRINT_ANY, "policy", "policy %s ",
			     netkit_print_policy(policy));
	}
	if (tb[IFLA_NETKIT_PEER_POLICY]) {
		__u32 policy = rta_getattr_u32(tb[IFLA_NETKIT_PEER_POLICY]);

		print_string(PRINT_ANY, "peer_policy", "peer policy %s ",
			     netkit_print_policy(policy));
	}
	if (tb[IFLA_NETKIT_SCRUB]) {
		enum netkit_scrub scrub = rta_getattr_u32(tb[IFLA_NETKIT_SCRUB]);

		print_string(PRINT_ANY, "scrub", "scrub %s ",
			     netkit_print_scrub(scrub));
	}
	if (tb[IFLA_NETKIT_PEER_SCRUB]) {
		enum netkit_scrub scrub = rta_getattr_u32(tb[IFLA_NETKIT_PEER_SCRUB]);

		print_string(PRINT_ANY, "peer_scrub", "peer scrub %s ",
			     netkit_print_scrub(scrub));
	}
}

static void netkit_print_help(struct link_util *lu,
			      int argc, char **argv, FILE *f)
{
	explain(lu, f);
}

struct link_util netkit_link_util = {
	.id		= "netkit",
	.maxattr	= IFLA_NETKIT_MAX,
	.parse_opt	= netkit_parse_opt,
	.print_opt	= netkit_print_opt,
	.print_help	= netkit_print_help,
};
