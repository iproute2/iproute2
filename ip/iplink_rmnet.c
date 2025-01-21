/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iplink_rmnet.c	RMNET device support
 *
 * Authors:     Daniele Palmas <dnlplm@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "ip_common.h"

static void print_explain(FILE *f)
{
	fprintf(f,
		"Usage: ... rmnet mux_id MUXID\n"
		"		[ ingress-deaggregation { on | off } ]\n"
		"		[ ingress-commands { on | off } ]\n"
		"		[ ingress-mapv4-checksum { on | off } ]\n"
		"		[ egress-mapv4-checksum { on | off } ]\n"
		"		[ ingress-mapv5-checksum { on | off } ]\n"
		"		[ egress-mapv5-checksum { on | off } ]\n"
		"\n"
		"MUXID := 1-254\n"
	);
}

static void explain(void)
{
	print_explain(stderr);
}

static int rmnet_parse_opt(struct link_util *lu, int argc, char **argv,
			   struct nlmsghdr *n)
{
	struct ifla_rmnet_flags flags = { 0 };
	__u16 mux_id;
	int ret;

	while (argc > 0) {
		if (strcmp(*argv, "mux_id") == 0) {
			NEXT_ARG();
			if (get_u16(&mux_id, *argv, 0))
				invarg("mux_id is invalid", *argv);
			addattr16(n, 1024, IFLA_RMNET_MUX_ID, mux_id);
		} else if (strcmp(*argv, "ingress-deaggregation") == 0) {
			bool deaggregation;

			NEXT_ARG();
			deaggregation = parse_on_off("ingress-deaggregation", *argv, &ret);
			if (ret)
				return ret;

			flags.mask |= RMNET_FLAGS_INGRESS_DEAGGREGATION;
			if (deaggregation)
				flags.flags |= RMNET_FLAGS_INGRESS_DEAGGREGATION;
			else
				flags.flags &= ~RMNET_FLAGS_INGRESS_DEAGGREGATION;
		} else if (strcmp(*argv, "ingress-commands") == 0) {
			bool commands;

			NEXT_ARG();
			commands = parse_on_off("ingress-commands", *argv, &ret);
			if (ret)
				return ret;

			flags.mask |= RMNET_FLAGS_INGRESS_MAP_COMMANDS;
			if (commands)
				flags.flags |= RMNET_FLAGS_INGRESS_MAP_COMMANDS;
			else
				flags.flags &= ~RMNET_FLAGS_INGRESS_MAP_COMMANDS;
		} else if (strcmp(*argv, "ingress-mapv4-checksum") == 0) {
			bool mapv4_checksum;

			NEXT_ARG();
			mapv4_checksum = parse_on_off("ingress-mapv4-checksum", *argv, &ret);
			if (ret)
				return ret;

			flags.mask |= RMNET_FLAGS_INGRESS_MAP_CKSUMV4;
			if (mapv4_checksum)
				flags.flags |= RMNET_FLAGS_INGRESS_MAP_CKSUMV4;
			else
				flags.flags &= ~RMNET_FLAGS_INGRESS_MAP_CKSUMV4;
		} else if (strcmp(*argv, "egress-mapv4-checksum") == 0) {
			bool mapv4_checksum;

			NEXT_ARG();
			mapv4_checksum = parse_on_off("egress-mapv4-checksum", *argv, &ret);
			if (ret)
				return ret;

			flags.mask |= RMNET_FLAGS_EGRESS_MAP_CKSUMV4;
			if (mapv4_checksum)
				flags.flags |= RMNET_FLAGS_EGRESS_MAP_CKSUMV4;
			else
				flags.flags &= ~RMNET_FLAGS_EGRESS_MAP_CKSUMV4;
		} else if (strcmp(*argv, "ingress-mapv5-checksum") == 0) {
			bool mapv5_checksum;

			NEXT_ARG();
			mapv5_checksum = parse_on_off("ingress-mapv5-checksum", *argv, &ret);
			if (ret)
				return ret;

			flags.mask |= RMNET_FLAGS_INGRESS_MAP_CKSUMV5;
			if (mapv5_checksum)
				flags.flags |= RMNET_FLAGS_INGRESS_MAP_CKSUMV5;
			else
				flags.flags &= ~RMNET_FLAGS_INGRESS_MAP_CKSUMV5;
		} else if (strcmp(*argv, "egress-mapv5-checksum") == 0) {
			bool mapv5_checksum;

			NEXT_ARG();
			mapv5_checksum = parse_on_off("egress-mapv5-checksum", *argv, &ret);
			if (ret)
				return ret;

			flags.mask |= RMNET_FLAGS_EGRESS_MAP_CKSUMV5;
			if (mapv5_checksum)
				flags.flags |= RMNET_FLAGS_EGRESS_MAP_CKSUMV5;
			else
				flags.flags &= ~RMNET_FLAGS_EGRESS_MAP_CKSUMV5;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "rmnet: unknown command \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--, argv++;
	}

	if (flags.mask)
		addattr_l(n, 1024, IFLA_RMNET_FLAGS, &flags, sizeof(flags));

	return 0;
}
static void rmnet_print_flags(FILE *fp, __u32 flags)
{
	open_json_array(PRINT_ANY, is_json_context() ? "flags" : "<");
#define _PF(f)	if (flags & RMNET_FLAGS_##f) {				\
		flags &= ~RMNET_FLAGS_##f;				\
		print_string(PRINT_ANY, NULL, flags ? "%s," : "%s", #f); \
	}
	_PF(INGRESS_DEAGGREGATION);
	_PF(INGRESS_MAP_COMMANDS);
	_PF(INGRESS_MAP_CKSUMV4);
	_PF(EGRESS_MAP_CKSUMV4);
	_PF(INGRESS_MAP_CKSUMV5);
	_PF(EGRESS_MAP_CKSUMV5);
#undef _PF
	if (flags)
		print_hex(PRINT_ANY, NULL, "%x", flags);
	close_json_array(PRINT_ANY, "> ");
}

static void rmnet_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	struct ifla_rmnet_flags *flags;

	if (!tb)
		return;

	if (!tb[IFLA_RMNET_MUX_ID] ||
	    RTA_PAYLOAD(tb[IFLA_RMNET_MUX_ID]) < sizeof(__u16))
		return;

	print_uint(PRINT_ANY,
		   "mux_id",
		   "mux_id %u ",
		   rta_getattr_u16(tb[IFLA_RMNET_MUX_ID]));

	if (tb[IFLA_RMNET_FLAGS]) {
		if (RTA_PAYLOAD(tb[IFLA_RMNET_FLAGS]) < sizeof(*flags))
			return;
		flags = RTA_DATA(tb[IFLA_RMNET_FLAGS]);
		rmnet_print_flags(f, flags->flags);
	}
}

static void rmnet_print_help(struct link_util *lu, int argc, char **argv,
			     FILE *f)
{
	print_explain(f);
}

struct link_util rmnet_link_util = {
	.id		= "rmnet",
	.maxattr	= IFLA_RMNET_MAX,
	.parse_opt	= rmnet_parse_opt,
	.print_opt	= rmnet_print_opt,
	.print_help	= rmnet_print_help,
};
