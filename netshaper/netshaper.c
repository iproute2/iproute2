/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iplink_netshaper.c netshaper H/W shaping support
 *
 * Authors:        Erni Sri Satya Vennela <ernis@linux.microsoft.com>
 */
#include <stdio.h>
#include <string.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/net_shaper.h>
#include "version.h"
#include "utils.h"
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
		"	    [bw-max BW_MAX]\n"
		"Where: DEVNAME         := STRING\n"
		"       HANDLE_SCOPE    := { netdev | queue | node }\n"
		"       HANDLE_ID       := UINT (required for queue/node, optional for netdev)\n"
		"       BW_MAX          := UINT{ kbit | mbit | gbit }\n");
}

static const char *net_shaper_scope_names[NET_SHAPER_SCOPE_MAX + 1] = {
	"unspec",
	"netdev",
	"queue",
	"node"
};

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

static int do_cmd(int argc, char **argv, struct nlmsghdr *n, int cmd)
{
	GENL_REQUEST(req, 1024, genl_family, 0, NET_SHAPER_FAMILY_VERSION, cmd,
		     NLM_F_REQUEST | NLM_F_ACK);

	struct nlmsghdr *answer;
	__u64 bw_max_bps = 0;
	int ifindex = -1;
	int handle_scope = NET_SHAPER_SCOPE_UNSPEC;
	__u32 handle_id = 0;
	bool handle_present = false;
	int err;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			ifindex = ll_name_to_index(*argv);
		} else if (strcmp(*argv, "bw-max") == 0) {
			NEXT_ARG();
			if (get_rate64(&bw_max_bps, *argv)) {
				fprintf(stderr, "Invalid bw-max value\n");
				return -1;
			}
			/* Convert Bps to bps */
			bw_max_bps *= 8;
		} else if (strcmp(*argv, "handle") == 0) {
			handle_present = true;
			NEXT_ARG();

			if (strcmp(*argv, "scope") != 0) {
				fprintf(stderr, "What is \"%s\"\n", *argv);
				usage();
				return -1;
			}
			NEXT_ARG();

			if (strcmp(*argv, "netdev") == 0) {
				handle_scope = NET_SHAPER_SCOPE_NETDEV;
				/* For netdev scope, id is optional - check if next arg is "id" */
				if (argc > 1 && strcmp(argv[1], "id") == 0) {
					NEXT_ARG(); /* move to "id" */
					NEXT_ARG(); /* move to id value */
					if (get_unsigned(&handle_id, *argv, 10)) {
						fprintf(stderr, "Invalid handle id\n");
						return -1;
					}
				}
			} else if (strcmp(*argv, "queue") == 0) {
				handle_scope = NET_SHAPER_SCOPE_QUEUE;
				/* For queue scope, id is required */
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
			} else if (strcmp(*argv, "node") == 0) {
				handle_scope = NET_SHAPER_SCOPE_NODE;
				/* For node scope, id is required */
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
			} else {
				fprintf(stderr, "Invalid scope\n");
				return -1;
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

	if (cmd == NET_SHAPER_CMD_SET && bw_max_bps == 0)
		missarg("bw-max");

	addattr32(&req.n, sizeof(req), NET_SHAPER_A_IFINDEX, ifindex);

	struct rtattr *handle = addattr_nest(&req.n, sizeof(req),
					     NET_SHAPER_A_HANDLE | NLA_F_NESTED);
	addattr32(&req.n, sizeof(req), NET_SHAPER_A_HANDLE_SCOPE, handle_scope);
	addattr32(&req.n, sizeof(req), NET_SHAPER_A_HANDLE_ID, handle_id);
	addattr_nest_end(&req.n, handle);

	if (cmd == NET_SHAPER_CMD_SET)
		addattr64(&req.n, sizeof(req), NET_SHAPER_A_BW_MAX, bw_max_bps);

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
	struct nlmsghdr *n;
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
			return do_cmd(argc - 1, argv + 1, n, NET_SHAPER_CMD_SET);
		if (strcmp(*argv, "delete") == 0)
			return do_cmd(argc - 1, argv + 1, n, NET_SHAPER_CMD_DELETE);
		if (strcmp(*argv, "show") == 0)
			return do_cmd(argc - 1, argv + 1, n, NET_SHAPER_CMD_GET);
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
