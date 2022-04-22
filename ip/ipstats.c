// SPDX-License-Identifier: GPL-2.0+
#include <errno.h>

#include "utils.h"
#include "ip_common.h"

static int do_help(void)
{
	fprintf(stderr,
		"Usage: ip stats help\n"
		"       ip stats set dev DEV l3_stats { on | off }\n"
		);

	return 0;
}

static int ipstats_set_do(int ifindex, int at, bool enable)
{
	struct ipstats_req req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct if_stats_msg)),
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_type = RTM_SETSTATS,
		.ifsm.family = PF_UNSPEC,
		.ifsm.ifindex = ifindex,
	};

	addattr8(&req.nlh, sizeof(req), at, enable);

	if (rtnl_talk(&rth, &req.nlh, NULL) < 0)
		return -2;
	return 0;
}

static int ipstats_set(int argc, char **argv)
{
	const char *dev = NULL;
	bool enable = false;
	int ifindex;
	int at = 0;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			if (dev)
				duparg2("dev", *argv);
			if (check_ifname(*argv))
				invarg("\"dev\" not a valid ifname", *argv);
			dev = *argv;
		} else if (strcmp(*argv, "l3_stats") == 0) {
			int err;

			NEXT_ARG();
			if (at) {
				fprintf(stderr, "A statistics suite to toggle was already given.\n");
				return -EINVAL;
			}
			at = IFLA_STATS_SET_OFFLOAD_XSTATS_L3_STATS;
			enable = parse_on_off("l3_stats", *argv, &err);
			if (err)
				return err;
		} else if (strcmp(*argv, "help") == 0) {
			do_help();
			return 0;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			do_help();
			return -EINVAL;
		}

		NEXT_ARG_FWD();
	}

	if (!dev) {
		fprintf(stderr, "Not enough information: \"dev\" argument is required.\n");
		exit(-1);
	}

	if (!at) {
		fprintf(stderr, "Not enough information: stat type to toggle is required.\n");
		exit(-1);
	}

	ifindex = ll_name_to_index(dev);
	if (!ifindex)
		return nodev(dev);

	return ipstats_set_do(ifindex, at, enable);
}

int do_ipstats(int argc, char **argv)
{
	int rc;

	if (argc == 0) {
		do_help();
		rc = -1;
	} else if (strcmp(*argv, "help") == 0) {
		do_help();
		rc = 0;
	} else if (strcmp(*argv, "set") == 0) {
		rc = ipstats_set(argc-1, argv+1);
	} else {
		fprintf(stderr, "Command \"%s\" is unknown, try \"ip stats help\".\n",
			*argv);
		rc = -1;
	}

	return rc;
}
