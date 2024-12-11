/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Get/set Multiple Spanning Tree (MST) states
 */

#include <stdio.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <net/if.h>

#include "libnetlink.h"
#include "json_print.h"
#include "utils.h"

#include "br_common.h"

#define MST_ID_LEN 9

#define __stringify_1(x...) #x
#define __stringify(x...) __stringify_1(x)

static unsigned int filter_index;

static void usage(void)
{
	fprintf(stderr,
		"Usage: bridge mst set dev DEV msti MSTI state STATE\n"
		"       bridge mst {show} [ dev DEV ]\n");
	exit(-1);
}

static void print_mst_entry(struct rtattr *a, FILE *fp)
{
	struct rtattr *tb[IFLA_BRIDGE_MST_ENTRY_MAX + 1];
	__u16 msti = 0;
	__u8 state = 0;

	parse_rtattr_flags(tb, IFLA_BRIDGE_MST_ENTRY_MAX, RTA_DATA(a),
			   RTA_PAYLOAD(a), NLA_F_NESTED);


	if (!(tb[IFLA_BRIDGE_MST_ENTRY_MSTI] &&
	      tb[IFLA_BRIDGE_MST_ENTRY_STATE])) {
		fprintf(stderr, "BUG: broken MST entry");
		return;
	}

	msti = rta_getattr_u16(tb[IFLA_BRIDGE_MST_ENTRY_MSTI]);
	state = rta_getattr_u8(tb[IFLA_BRIDGE_MST_ENTRY_STATE]);

	open_json_object(NULL);
	print_uint(PRINT_ANY, "msti", "%u", msti);
	print_nl();
	print_string(PRINT_FP, NULL, "%-" __stringify(IFNAMSIZ) "s    ", "");
	print_stp_state(state);
	print_nl();
	close_json_object();
}

static int print_msts(struct nlmsghdr *n, void *arg)
{
	struct ifinfomsg *ifi = NLMSG_DATA(n);
	struct rtattr *af_spec, *mst, *a;
	int rem = n->nlmsg_len;
	bool opened = false;

	rem -= NLMSG_LENGTH(sizeof(*ifi));
	if (rem < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", rem);
		return -1;
	}

	af_spec = parse_rtattr_one(IFLA_AF_SPEC, IFLA_RTA(ifi), rem);
	if (!af_spec)
		return -1;

	if (filter_index && filter_index != ifi->ifi_index)
		return 0;

	mst = parse_rtattr_one_nested(NLA_F_NESTED | IFLA_BRIDGE_MST, af_spec);
	if (!mst)
		return 0;

	rem = RTA_PAYLOAD(mst);
	for (a = RTA_DATA(mst); RTA_OK(a, rem); a = RTA_NEXT(a, rem)) {
		unsigned short rta_type = a->rta_type & NLA_TYPE_MASK;

		if (rta_type > IFLA_BRIDGE_MST_MAX)
			continue;

		switch (rta_type) {
		case IFLA_BRIDGE_MST_ENTRY:
			if (!opened) {
				open_json_object(NULL);
				print_color_string(PRINT_ANY, COLOR_IFNAME,
						   "ifname",
						   "%-" __stringify(IFNAMSIZ) "s  ",
						   ll_index_to_name(ifi->ifi_index));
				open_json_array(PRINT_JSON, "mst");
				opened = true;
			} else {
				print_string(PRINT_FP, NULL, "%-"
					     __stringify(IFNAMSIZ) "s  ", "");
			}

			print_mst_entry(a, arg);
			break;
		}
	}

	if (opened) {
		close_json_array(PRINT_JSON, NULL);
		close_json_object();
	}

	return 0;
}

static int mst_show(int argc, char **argv)
{
	char *filter_dev = NULL;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			if (filter_dev)
				duparg("dev", *argv);
			filter_dev = *argv;
		}
		argc--; argv++;
	}

	if (filter_dev) {
		filter_index = ll_name_to_index(filter_dev);
		if (!filter_index)
			return nodev(filter_dev);
	}

	if (rtnl_linkdump_req_filter(&rth, PF_BRIDGE, RTEXT_FILTER_MST) < 0) {
		perror("Cannon send dump request");
		exit(1);
	}

	new_json_obj(json);

	if (!is_json_context()) {
		printf("%-" __stringify(IFNAMSIZ) "s  "
		       "%-" __stringify(MST_ID_LEN) "s",
		       "port", "msti");
		printf("\n");
	}

	if (rtnl_dump_filter(&rth, print_msts, stdout) < 0) {
		fprintf(stderr, "Dump terminated\n");
		delete_json_obj();
		return -1;
	}

	delete_json_obj();
	fflush(stdout);
	return 0;
}

static int mst_set(int argc, char **argv)
{
	struct {
		struct nlmsghdr		n;
		struct ifinfomsg	ifi;
		char			buf[512];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_SETLINK,
		.ifi.ifi_family = PF_BRIDGE,
	};
	char *d = NULL, *m = NULL, *s = NULL, *endptr;
	struct rtattr *af_spec, *mst, *entry;
	__u16 msti;
	int state;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			d = *argv;
		} else if (strcmp(*argv, "msti") == 0) {
			NEXT_ARG();
			m = *argv;
		} else if (strcmp(*argv, "state") == 0) {
			NEXT_ARG();
			s = *argv;
		} else {
			if (matches(*argv, "help") == 0)
				usage();
		}
		argc--; argv++;
	}

	if (d == NULL || m == NULL || s == NULL) {
		fprintf(stderr, "Device, MSTI and state are required arguments.\n");
		return -1;
	}

	req.ifi.ifi_index = ll_name_to_index(d);
	if (!req.ifi.ifi_index)
		return nodev(d);

	msti = strtol(m, &endptr, 10);
	if (!(*s != '\0' && *endptr == '\0')) {
		fprintf(stderr,
			"Error: invalid MSTI\n");
		return -1;
	}

	state = strtol(s, &endptr, 10);
	if (!(*s != '\0' && *endptr == '\0'))
		state = parse_stp_state(s);
	
	if (state < 0 || state > UINT8_MAX) {
		fprintf(stderr, "Error: invalid STP port state\n");
		return -1;
	}

	af_spec = addattr_nest(&req.n, sizeof(req), IFLA_AF_SPEC);
	mst = addattr_nest(&req.n, sizeof(req), IFLA_BRIDGE_MST);

	entry = addattr_nest(&req.n, sizeof(req), IFLA_BRIDGE_MST_ENTRY);
	entry->rta_type |= NLA_F_NESTED;

	addattr16(&req.n, sizeof(req), IFLA_BRIDGE_MST_ENTRY_MSTI, msti);
	addattr8(&req.n, sizeof(req), IFLA_BRIDGE_MST_ENTRY_STATE, state);

	addattr_nest_end(&req.n, entry);

	addattr_nest_end(&req.n, mst);
	addattr_nest_end(&req.n, af_spec);


	if (rtnl_talk(&rth, &req.n, NULL) < 0)
		return -1;

	return 0;
}

int do_mst(int argc, char **argv)
{
	ll_init_map(&rth);

	if (argc > 0) {
		if (matches(*argv, "set") == 0)
			return mst_set(argc-1, argv+1);

		if (matches(*argv, "show") == 0 ||
		    matches(*argv, "lst") == 0 ||
		    matches(*argv, "list") == 0)
			return mst_show(argc-1, argv+1);
		if (matches(*argv, "help") == 0)
			usage();
	} else
		return mst_show(0, NULL);

	fprintf(stderr, "Command \"%s\" is unknown, try \"bridge mst help\".\n", *argv);
	exit(-1);
}
