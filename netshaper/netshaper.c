/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iplink_netshaper.c netshaper H/W shaping support
 *
 * Authors:        Erni Sri Satya Vennela <ernis@linux.microsoft.com>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/net_shaper.h>

#include "version.h"
#include "utils.h"
#include "ll_map.h"
#include "color.h"
#include "json_print.h"
#include "libgenl.h"
#include "libnetlink.h"

/* netlink socket */
static struct rtnl_handle gen_rth = { .fd = -1 };
static int genl_family = -1;

static void usage(void)
{
	fprintf(stderr,
		"Usage: netshaper [ OPTIONS ] { COMMAND | help }\n"
		"OPTIONS := { -V[ersion] | -c[olor] | -help }\n"
		"COMMAND := { set | get | delete } dev DEVNAME\n"
		"	    handle scope HANDLE_SCOPE [id HANDLE_ID]\n"
		"	    [bw-min BW_MIN] [bw-max BW_MAX] [weight WEIGHT]\n"
		"\n"
		"Where: DEVNAME         := STRING\n"
		"       HANDLE_SCOPE    := { netdev | queue | node }\n"
		"       HANDLE_ID       := UINT (required for queue/node, optional for netdev)\n"
		"       BW_MIN/BW_MAX   := UINT{ kbit | mbit | gbit }\n"
		"       WEIGHT          := UINT\n");
}

static const char *net_shaper_scope_names[NET_SHAPER_SCOPE_MAX + 1] = {
	"unspec",
	"netdev",
	"queue",
	"node"
};

static int parse_scope(const char *str)
{
	for (int i = 1; i <= NET_SHAPER_SCOPE_MAX; i++) {
		if (strcmp(str, net_shaper_scope_names[i]) == 0)
			return i;
	}
	return -1;
}

static int parse_rate(const char *str, __u64 *rate_bps)
{
	if (get_rate64(rate_bps, str)) {
		fprintf(stderr, "Invalid rate value \"%s\"\n", str);
		return -1;
	}
	/* get_rate64 returns bytes/sec, convert to bits/sec */
	*rate_bps *= BITS_PER_BYTE;
	return 0;
}

static void print_netshaper_attrs(struct nlmsghdr *answer)
{
	struct genlmsghdr *ghdr = NLMSG_DATA(answer);
	int len = answer->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	struct rtattr *tb[NET_SHAPER_A_MAX + 1] = {};
	struct rtattr *handle_tb[NET_SHAPER_A_HANDLE_MAX + 1] = {};
	__u32 bw_max_mbps, scope, id;
	__u64 bw_max_bps;
	int ifindex;

	parse_rtattr_flags(tb, NET_SHAPER_A_MAX,
			   (struct rtattr *)((char *)ghdr + GENL_HDRLEN),
			   len, NLA_F_NESTED);

	for (int i = 1; i <= NET_SHAPER_A_MAX; ++i) {
		if (!tb[i])
			continue;
		switch (i) {
		case NET_SHAPER_A_BW_MAX:
			bw_max_bps = rta_getattr_uint(tb[i]);
			bw_max_mbps = (bw_max_bps / 1000000);

			print_uint(PRINT_ANY, "bw-max", "bw-max: %u mbps\n",
				   bw_max_mbps);
			break;
		case NET_SHAPER_A_IFINDEX:
			ifindex = rta_getattr_u32(tb[i]);
			print_color_string(PRINT_ANY, COLOR_IFNAME, "dev",
					   "dev: %s\n",
					   ll_index_to_name(ifindex));
			break;
		case NET_SHAPER_A_HANDLE:
			parse_rtattr_nested(handle_tb, NET_SHAPER_A_HANDLE_MAX,
					    tb[NET_SHAPER_A_HANDLE]);
			if (handle_tb[NET_SHAPER_A_HANDLE_SCOPE]) {
				scope = rta_getattr_u32(handle_tb[NET_SHAPER_A_HANDLE_SCOPE]);
				print_string(PRINT_ANY, "scope",
					     "scope: %s\n",
					     net_shaper_scope_names[scope]);
			}
			if (handle_tb[NET_SHAPER_A_HANDLE_ID]) {
				id = rta_getattr_u32(handle_tb[NET_SHAPER_A_HANDLE_ID]);
				print_uint(PRINT_ANY, "id", "id: %u\n", id);
			}
			break;
		default:
			break;
		}
	}
}

static int do_cmd(int argc, char **argv, int cmd)
{
	GENL_REQUEST(req, 1024, genl_family, 0, NET_SHAPER_FAMILY_VERSION, cmd,
		     NLM_F_REQUEST | NLM_F_ACK);

	bool has_bw_min = false, has_bw_max = false, has_weight = false;
	int handle_scope = NET_SHAPER_SCOPE_UNSPEC;
	__u64 bw_min_bps = 0, bw_max_bps = 0;
	__u32 handle_id = 0, weight = 0;
	bool handle_present = false;
	bool has_handle_id = false;
	struct nlmsghdr *answer;
	int err, ifindex = -1;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			ifindex = ll_name_to_index(*argv);
			if (ifindex == 0) {
				fprintf(stderr, "Device \"%s\" not found\n", *argv);
				return -1;
			}
		} else if (strcmp(*argv, "bw-min") == 0) {
			NEXT_ARG();
			if (parse_rate(*argv, &bw_min_bps))
				return -1;
			has_bw_min = true;
		} else if (strcmp(*argv, "bw-max") == 0) {
			NEXT_ARG();
			if (parse_rate(*argv, &bw_max_bps))
				return -1;
			has_bw_max = true;
		} else if (strcmp(*argv, "weight") == 0) {
			NEXT_ARG();
			if (get_unsigned(&weight, *argv, 10)) {
				fprintf(stderr, "Invalid weight value\n");
				return -1;
			}
			has_weight = true;
		} else if (strcmp(*argv, "handle") == 0) {
			handle_present = true;
			NEXT_ARG();

			if (strcmp(*argv, "scope") != 0) {
				fprintf(stderr, "What is \"%s\"\n", *argv);
				usage();
				return -1;
			}
			NEXT_ARG();

			handle_scope = parse_scope(*argv);
			if (handle_scope < 0) {
				fprintf(stderr, "Invalid scope \"%s\"\n", *argv);
				return -1;
			}

			if (handle_scope == NET_SHAPER_SCOPE_NETDEV) {
				/* For netdev scope, id is optional */
				if (argc > 1 && strcmp(argv[1], "id") == 0) {
					NEXT_ARG();
					NEXT_ARG();
					if (get_unsigned(&handle_id, *argv, 10)) {
						fprintf(stderr, "Invalid handle id\n");
						return -1;
					}
					has_handle_id = true;
				}
			} else {
				/* For queue/node scope, id is required */
				NEXT_ARG();
				if (strcmp(*argv, "id") != 0) {
					fprintf(stderr, "What is \"%s\"\n", *argv);
					usage();
					return -1;
				}
				NEXT_ARG();
				if (get_unsigned(&handle_id, *argv, 10)) {
					fprintf(stderr, "Invalid handle id\n");
					return -1;
				}
				has_handle_id = true;
			}
		} else {
			fprintf(stderr, "What is \"%s\"\n", *argv);
			usage();
			return -1;
		}
		argc--;
		argv++;
	}

	if (ifindex == -1)
		missarg("dev");

	if (!handle_present)
		missarg("handle");

	if (cmd == NET_SHAPER_CMD_SET && !has_bw_min && !has_bw_max && !has_weight)
		missarg("bw-min, bw-max, or weight");

	addattr32(&req.n, sizeof(req), NET_SHAPER_A_IFINDEX, ifindex);

	struct rtattr *handle = addattr_nest(&req.n, sizeof(req),
					     NET_SHAPER_A_HANDLE | NLA_F_NESTED);
	addattr32(&req.n, sizeof(req), NET_SHAPER_A_HANDLE_SCOPE, handle_scope);
	if (has_handle_id)
		addattr32(&req.n, sizeof(req), NET_SHAPER_A_HANDLE_ID, handle_id);
	addattr_nest_end(&req.n, handle);

	if (cmd == NET_SHAPER_CMD_SET) {
		if (has_bw_min)
			addattr64(&req.n, sizeof(req), NET_SHAPER_A_BW_MIN,
				  bw_min_bps);
		if (has_bw_max)
			addattr64(&req.n, sizeof(req), NET_SHAPER_A_BW_MAX,
				  bw_max_bps);
		if (has_weight)
			addattr32(&req.n, sizeof(req), NET_SHAPER_A_WEIGHT,
				  weight);
		if (has_bw_min || has_bw_max)
			addattr32(&req.n, sizeof(req), NET_SHAPER_A_METRIC,
				  NET_SHAPER_METRIC_BPS);
	}

	err = rtnl_talk(&gen_rth, &req.n, &answer);
	if (err < 0) {
		printf("Kernel command failed: %d\n", err);
		return err;
	}

	if (cmd == NET_SHAPER_CMD_GET)
		print_netshaper_attrs(answer);

	return err;
}

int main(int argc, char **argv)
{
	int color = default_color_opt();

	while (argc > 1) {
		const char *opt = argv[1];

		if (opt[0] != '-')
			break;
		if (opt[1] == '-')
			opt++;

		if (strcmp(opt, "-help") == 0) {
			usage();
			exit(0);
		} else if (strcmp(opt, "-Version") == 0 ||
			   strcmp(opt, "-V") == 0) {
			printf("netshaper utility, %s\n", version);
			exit(0);
		} else if (matches_color(opt, &color)) {
		} else {
			fprintf(stderr,
				"Option \"%s\" is unknown, try \"netshaper help\".\n",
				opt);
			exit(-1);
		}
		argc--; argv++;
	}

	check_enable_color(color, 0);

	if (genl_init_handle(&gen_rth, NET_SHAPER_FAMILY_NAME, &genl_family))
		exit(1);

	if (argc > 1) {
		argc--;
		argv++;

		if (strcmp(*argv, "set") == 0)
			return do_cmd(argc - 1, argv + 1, NET_SHAPER_CMD_SET);
		if (strcmp(*argv, "delete") == 0)
			return do_cmd(argc - 1, argv + 1, NET_SHAPER_CMD_DELETE);
		if (strcmp(*argv, "show") == 0)
			return do_cmd(argc - 1, argv + 1, NET_SHAPER_CMD_GET);
		if (strcmp(*argv, "help") == 0) {
			usage();
			return 0;
		}
		fprintf(stderr,
			"Command \"%s\" is unknown, try \"netshaper help\".\n",
			*argv);
		exit(-1);
	}
	usage();
	exit(-1);
}
