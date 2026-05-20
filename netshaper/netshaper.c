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
		"COMMAND := { set | get | delete | group } dev DEVNAME\n"
		"	    handle scope HANDLE_SCOPE [id HANDLE_ID]\n"
		"	    [bw-min BW_MIN] [bw-max BW_MAX] [weight WEIGHT]\n"
		"\n"
		"netshaper group dev DEVNAME handle scope SCOPE [ id ID ]\n"
		"          [ parent scope SCOPE [ id ID ] ]\n"
		"          [ bw-min BW ] [ bw-max BW ] [ weight WEIGHT ]\n"
		"          leaves { scope queue id ID\n"
		"          [ weight WEIGHT ] [ priority PRIO ] } [ ... ]\n"
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

struct shaper_leaf {
	__u32 id;
	__u32 weight;
	__u32 priority;
	int scope;
	bool has_weight;
	bool has_priority;
};

struct shaper_args {
	__u64 bw_min_bps, bw_max_bps;
	__u32 weight;
	bool has_bw_min, has_bw_max, has_weight;
	int ifindex;
};

#define SHAPER_ARGS_INIT { .ifindex = -1 }


static int parse_shaper_arg(const char *key, int *argcp, char ***argvp,
			    struct shaper_args *args)
{
	int argc = *argcp;
	char **argv = *argvp;

	if (strcmp(key, "dev") == 0) {
		NEXT_ARG();
		args->ifindex = ll_name_to_index(*argv);
		if (args->ifindex == 0) {
			fprintf(stderr, "Device \"%s\" not found\n", *argv);
			return -1;
		}
	} else if (strcmp(key, "bw-min") == 0) {
		NEXT_ARG();
		if (parse_rate(*argv, &args->bw_min_bps))
			return -1;
		args->has_bw_min = true;
	} else if (strcmp(key, "bw-max") == 0) {
		NEXT_ARG();
		if (parse_rate(*argv, &args->bw_max_bps))
			return -1;
		args->has_bw_max = true;
	} else if (strcmp(key, "weight") == 0) {
		NEXT_ARG();
		if (get_unsigned(&args->weight, *argv, 10)) {
			fprintf(stderr, "Invalid weight value\n");
			return -1;
		}
		args->has_weight = true;
	} else {
		return 0;
	}

	*argcp = argc;
	*argvp = argv;
	return 1;
}

static void print_netshaper_attrs(struct nlmsghdr *answer)
{
	struct rtattr *handle_tb[NET_SHAPER_A_HANDLE_MAX + 1] = {};
	struct rtattr *parent_tb[NET_SHAPER_A_HANDLE_MAX + 1] = {};
	int len = answer->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	struct genlmsghdr *ghdr = NLMSG_DATA(answer);
	struct rtattr *tb[NET_SHAPER_A_MAX + 1] = {};
	__u32 scope, id;
	int ifindex;

	parse_rtattr_flags(tb, NET_SHAPER_A_MAX,
			   (struct rtattr *)((char *)ghdr + GENL_HDRLEN),
			   len, NLA_F_NESTED);

	if (tb[NET_SHAPER_A_IFINDEX]) {
		ifindex = rta_getattr_u32(tb[NET_SHAPER_A_IFINDEX]);
		print_color_string(PRINT_ANY, COLOR_IFNAME, "dev",
				   "dev: %s ", ll_index_to_name(ifindex));
	}

	if (tb[NET_SHAPER_A_HANDLE]) {
		parse_rtattr_nested(handle_tb, NET_SHAPER_A_HANDLE_MAX,
				    tb[NET_SHAPER_A_HANDLE]);
		if (handle_tb[NET_SHAPER_A_HANDLE_SCOPE]) {
			scope = rta_getattr_u32(handle_tb[NET_SHAPER_A_HANDLE_SCOPE]);
			if (scope <= NET_SHAPER_SCOPE_MAX)
				print_string(PRINT_ANY, "scope", "scope %s ",
					     net_shaper_scope_names[scope]);
			else
				print_uint(PRINT_ANY, "scope", "scope %u ", scope);
		}
		if (handle_tb[NET_SHAPER_A_HANDLE_ID]) {
			id = rta_getattr_u32(handle_tb[NET_SHAPER_A_HANDLE_ID]);
			print_uint(PRINT_ANY, "id", "id %u ", id);
		}
	}

	if (tb[NET_SHAPER_A_PARENT]) {
		parse_rtattr_nested(parent_tb, NET_SHAPER_A_HANDLE_MAX,
				    tb[NET_SHAPER_A_PARENT]);
		if (parent_tb[NET_SHAPER_A_HANDLE_SCOPE]) {
			scope = rta_getattr_u32(parent_tb[NET_SHAPER_A_HANDLE_SCOPE]);
			if (scope <= NET_SHAPER_SCOPE_MAX)
				print_string(PRINT_ANY, "parent-scope",
					     "parent scope %s ",
					     net_shaper_scope_names[scope]);
			else
				print_uint(PRINT_ANY, "parent-scope",
					   "parent scope %u ", scope);
		}
		if (parent_tb[NET_SHAPER_A_HANDLE_ID]) {
			id = rta_getattr_u32(parent_tb[NET_SHAPER_A_HANDLE_ID]);
			print_uint(PRINT_ANY, "parent-id", "id %u ", id);
		}
	}

	if (tb[NET_SHAPER_A_BW_MAX]) {
		__u64 bw = rta_getattr_uint(tb[NET_SHAPER_A_BW_MAX]);

		print_string(PRINT_FP, NULL, "bw-max ", NULL);
		print_rate(false, PRINT_ANY, "bw-max", "%s ",
			   bw / BITS_PER_BYTE);
	}

	if (tb[NET_SHAPER_A_BW_MIN]) {
		__u64 bw = rta_getattr_uint(tb[NET_SHAPER_A_BW_MIN]);

		print_string(PRINT_FP, NULL, "bw-min ", NULL);
		print_rate(false, PRINT_ANY, "bw-min", "%s ",
			   bw / BITS_PER_BYTE);
	}

	if (tb[NET_SHAPER_A_WEIGHT]) {
		__u32 weight = rta_getattr_u32(tb[NET_SHAPER_A_WEIGHT]);

		print_uint(PRINT_ANY, "weight", "weight %u ", weight);
	}

	print_nl();
}

static int do_cmd(int argc, char **argv, int cmd)
{
	GENL_REQUEST(req, 1024, genl_family, 0, NET_SHAPER_FAMILY_VERSION, cmd,
		     NLM_F_REQUEST | NLM_F_ACK);

	struct shaper_args args = SHAPER_ARGS_INIT;
	int handle_scope = NET_SHAPER_SCOPE_UNSPEC;
	bool handle_present = false;
	bool has_handle_id = false;
	struct nlmsghdr *answer;
	__u32 handle_id = 0;
	int err, ret;

	while (argc > 0) {
		ret = parse_shaper_arg(*argv, &argc, &argv, &args);
		if (ret < 0)
			return -1;
		if (ret > 0) {
			argc--;
			argv++;
			continue;
		}

		if (strcmp(*argv, "handle") == 0) {
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

	if (args.ifindex == -1)
		missarg("dev");

	if (!handle_present)
		missarg("handle");

	if (cmd == NET_SHAPER_CMD_SET &&
	    !args.has_bw_min && !args.has_bw_max && !args.has_weight)
		missarg("bw-min, bw-max, or weight");

	addattr32(&req.n, sizeof(req), NET_SHAPER_A_IFINDEX, args.ifindex);

	struct rtattr *handle = addattr_nest(&req.n, sizeof(req),
					     NET_SHAPER_A_HANDLE | NLA_F_NESTED);
	addattr32(&req.n, sizeof(req), NET_SHAPER_A_HANDLE_SCOPE, handle_scope);
	if (has_handle_id)
		addattr32(&req.n, sizeof(req), NET_SHAPER_A_HANDLE_ID, handle_id);
	addattr_nest_end(&req.n, handle);

	if (cmd == NET_SHAPER_CMD_SET) {
		if (args.has_bw_min)
			addattr64(&req.n, sizeof(req), NET_SHAPER_A_BW_MIN,
				  args.bw_min_bps);
		if (args.has_bw_max)
			addattr64(&req.n, sizeof(req), NET_SHAPER_A_BW_MAX,
				  args.bw_max_bps);
		if (args.has_weight)
			addattr32(&req.n, sizeof(req), NET_SHAPER_A_WEIGHT,
				  args.weight);
		if (args.has_bw_min || args.has_bw_max)
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

static int parse_scope_id(const char *what, int *argcp, char ***argvp, int *scopep,
			  __u32 *idp, bool *has_idp, bool require_node_id)
{
	char **argv = *argvp;
	int argc = *argcp;
	int scope;

	NEXT_ARG();
	if (strcmp(*argv, "scope") != 0) {
		fprintf(stderr, "Expected \"scope\" after \"%s\"\n", what);
		return -1;
	}

	NEXT_ARG();
	scope = parse_scope(*argv);
	if (scope < 0) {
		fprintf(stderr, "Invalid %s scope \"%s\"\n", what, *argv);
		return -1;
	}
	if (scope != NET_SHAPER_SCOPE_NODE && scope != NET_SHAPER_SCOPE_NETDEV) {
		fprintf(stderr, "%s scope must be \"node\" or \"netdev\"\n", what);
		return -1;
	}

	if (require_node_id && scope == NET_SHAPER_SCOPE_NODE) {
		NEXT_ARG();
		if (strcmp(*argv, "id") != 0) {
			fprintf(stderr, "What is \"%s\"\n", *argv);
			usage();
			return -1;
		}
		NEXT_ARG();
		if (get_unsigned(idp, *argv, 10)) {
			fprintf(stderr, "Invalid %s id\n", what);
			return -1;
		}
		*has_idp = true;
	} else if (argc > 1 && strcmp(argv[1], "id") == 0) {
		NEXT_ARG();
		NEXT_ARG();
		if (get_unsigned(idp, *argv, 10)) {
			fprintf(stderr, "Invalid %s id\n", what);
			return -1;
		}
		*has_idp = true;
	}

	*scopep = scope;
	*argcp = argc;
	*argvp = argv;
	return 0;
}

static int parse_leaves(int *argcp, char ***argvp,
			struct shaper_leaf **leavesp)
{
	struct shaper_leaf *leaves = NULL;
	int count = 0, cap = 0;
	char **argv = *argvp;
	int argc = *argcp;

	while (argc > 0 && strcmp(*argv, "scope") == 0) {
		int lscope;

		if (count >= cap) {
			cap = cap ? cap * 2 : 8;
			leaves = realloc(leaves, cap * sizeof(*leaves));
			if (!leaves)
				return -1;
		}

		NEXT_ARG();
		lscope = parse_scope(*argv);
		if (lscope < 0) {
			fprintf(stderr, "Invalid leaf scope \"%s\"\n", *argv);
			free(leaves);
			return -1;
		}
		if (lscope != NET_SHAPER_SCOPE_QUEUE) {
			fprintf(stderr, "Leaf scope must be \"queue\"\n");
			free(leaves);
			return -1;
		}

		NEXT_ARG();
		if (strcmp(*argv, "id") != 0) {
			fprintf(stderr, "Expected \"id\" after leaf scope\n");
			free(leaves);
			return -1;
		}

		NEXT_ARG();
		leaves[count].scope = lscope;
		leaves[count].has_weight = false;
		leaves[count].has_priority = false;
		if (get_unsigned(&leaves[count].id, *argv, 10)) {
			fprintf(stderr, "Invalid leaf id\n");
			free(leaves);
			return -1;
		}
		argc--;
		argv++;

		while (argc > 0 && strcmp(*argv, "scope") != 0) {
			if (strcmp(*argv, "weight") == 0) {
				NEXT_ARG();
				if (get_unsigned(&leaves[count].weight,
						 *argv, 10)) {
					fprintf(stderr,
						"Invalid leaf weight\n");
					free(leaves);
					return -1;
				}
				leaves[count].has_weight = true;
			} else if (strcmp(*argv, "priority") == 0) {
				NEXT_ARG();
				if (get_unsigned(&leaves[count].priority,
						 *argv, 10)) {
					fprintf(stderr,
						"Invalid leaf priority\n");
					free(leaves);
					return -1;
				}
				leaves[count].has_priority = true;
			} else {
				break;
			}
			argc--;
			argv++;
		}
		count++;
	}

	*argcp = argc;
	*argvp = argv;
	*leavesp = leaves;
	return count;
}

static int do_group(int argc, char **argv)
{
	GENL_REQUEST(req, 4096, genl_family, 0, NET_SHAPER_FAMILY_VERSION,
		     NET_SHAPER_CMD_GROUP, NLM_F_REQUEST | NLM_F_ACK);

	bool has_handle_id = false, has_parent_id = false;
	struct shaper_args args = SHAPER_ARGS_INIT;
	int handle_scope = NET_SHAPER_SCOPE_UNSPEC;
	int parent_scope = -1, num_leaves = 0;
	__u32 handle_id = 0, parent_id = 0;
	struct shaper_leaf *leaves = NULL;
	struct nlmsghdr *answer;
	struct rtattr *nest;
	int err, ret;

	while (argc > 0) {
		ret = parse_shaper_arg(*argv, &argc, &argv, &args);
		if (ret < 0)
			goto free_leaves;
		if (ret > 0) {
			argc--;
			argv++;
			continue;
		}

		if (strcmp(*argv, "handle") == 0) {
			if (parse_scope_id("handle", &argc, &argv,
					   &handle_scope, &handle_id,
					   &has_handle_id, false))
				goto free_leaves;
		} else if (strcmp(*argv, "parent") == 0) {
			if (parse_scope_id("parent", &argc, &argv,
					   &parent_scope, &parent_id,
					   &has_parent_id, true))
				goto free_leaves;
		} else if (strcmp(*argv, "leaves") == 0) {
			NEXT_ARG();
			num_leaves = parse_leaves(&argc, &argv, &leaves);
			if (num_leaves < 0)
				return -1;
			continue;
		} else {
			fprintf(stderr, "What is \"%s\"\n", *argv);
			usage();
			goto free_leaves;
		}
		argc--;
		argv++;
	}

	if (args.ifindex == -1)
		missarg("dev");
	if (handle_scope == NET_SHAPER_SCOPE_UNSPEC)
		missarg("handle");
	if (num_leaves == 0)
		missarg("leaves");

	addattr32(&req.n, sizeof(req), NET_SHAPER_A_IFINDEX, args.ifindex);

	if (parent_scope >= 0) {
		nest = addattr_nest(&req.n, sizeof(req), NET_SHAPER_A_PARENT | NLA_F_NESTED);
		addattr32(&req.n, sizeof(req), NET_SHAPER_A_HANDLE_SCOPE, parent_scope);
		if (has_parent_id)
			addattr32(&req.n, sizeof(req), NET_SHAPER_A_HANDLE_ID, parent_id);
		addattr_nest_end(&req.n, nest);
	}

	nest = addattr_nest(&req.n, sizeof(req), NET_SHAPER_A_HANDLE | NLA_F_NESTED);
	addattr32(&req.n, sizeof(req), NET_SHAPER_A_HANDLE_SCOPE, handle_scope);
	if (has_handle_id)
		addattr32(&req.n, sizeof(req), NET_SHAPER_A_HANDLE_ID, handle_id);
	addattr_nest_end(&req.n, nest);

	if (args.has_bw_min)
		addattr64(&req.n, sizeof(req), NET_SHAPER_A_BW_MIN, args.bw_min_bps);
	if (args.has_bw_max)
		addattr64(&req.n, sizeof(req), NET_SHAPER_A_BW_MAX, args.bw_max_bps);
	if (args.has_weight)
		addattr32(&req.n, sizeof(req), NET_SHAPER_A_WEIGHT, args.weight);

	if (args.has_bw_min || args.has_bw_max)
		addattr32(&req.n, sizeof(req), NET_SHAPER_A_METRIC, NET_SHAPER_METRIC_BPS);

	for (int i = 0; i < num_leaves; i++) {
		struct rtattr *leaf, *handle;

		leaf = addattr_nest(&req.n, sizeof(req),
				    NET_SHAPER_A_LEAVES | NLA_F_NESTED);
		handle = addattr_nest(&req.n, sizeof(req),
				      NET_SHAPER_A_HANDLE | NLA_F_NESTED);
		addattr32(&req.n, sizeof(req),
			  NET_SHAPER_A_HANDLE_SCOPE, leaves[i].scope);
		addattr32(&req.n, sizeof(req),
			  NET_SHAPER_A_HANDLE_ID, leaves[i].id);
		addattr_nest_end(&req.n, handle);
		if (leaves[i].has_priority)
			addattr32(&req.n, sizeof(req),
				  NET_SHAPER_A_PRIORITY,
				  leaves[i].priority);
		if (leaves[i].has_weight)
			addattr32(&req.n, sizeof(req),
				  NET_SHAPER_A_WEIGHT,
				  leaves[i].weight);
		addattr_nest_end(&req.n, leaf);
	}

	err = rtnl_talk(&gen_rth, &req.n, &answer);
	if (err < 0) {
		fprintf(stderr, "Kernel command failed: %d\n", err);
		goto free_leaves;
	}

	print_netshaper_attrs(answer);
	free(answer);
	free(leaves);
	return 0;

free_leaves:
	free(leaves);
	return -1;
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
		if (strcmp(*argv, "group") == 0)
			return do_group(argc - 1, argv + 1);
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
