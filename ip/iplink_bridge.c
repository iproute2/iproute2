/*
 * iplink_bridge.c	Bridge device support
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Jiri Pirko <jiri@resnulli.us>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>
#include <netinet/ether.h>

#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"

static void print_explain(FILE *f)
{
	fprintf(f,
		"Usage: ... bridge [ forward_delay FORWARD_DELAY ]\n"
		"                  [ hello_time HELLO_TIME ]\n"
		"                  [ max_age MAX_AGE ]\n"
		"                  [ ageing_time AGEING_TIME ]\n"
		"                  [ stp_state STP_STATE ]\n"
		"                  [ priority PRIORITY ]\n"
		"                  [ group_fwd_mask MASK ]\n"
		"                  [ group_address ADDRESS ]\n"
		"                  [ vlan_filtering VLAN_FILTERING ]\n"
		"                  [ vlan_protocol VLAN_PROTOCOL ]\n"
		"                  [ vlan_default_pvid VLAN_DEFAULT_PVID ]\n"
		"                  [ mcast_snooping MULTICAST_SNOOPING ]\n"
		"                  [ mcast_router MULTICAST_ROUTER ]\n"
		"                  [ mcast_query_use_ifaddr MCAST_QUERY_USE_IFADDR ]\n"
		"                  [ mcast_querier MULTICAST_QUERIER ]\n"
		"                  [ mcast_hash_elasticity HASH_ELASTICITY ]\n"
		"                  [ mcast_hash_max HASH_MAX ]\n"
		"                  [ mcast_last_member_count LAST_MEMBER_COUNT ]\n"
		"                  [ mcast_startup_query_count STARTUP_QUERY_COUNT ]\n"
		"                  [ mcast_last_member_interval LAST_MEMBER_INTERVAL ]\n"
		"                  [ mcast_membership_interval MEMBERSHIP_INTERVAL ]\n"
		"                  [ mcast_querier_interval QUERIER_INTERVAL ]\n"
		"                  [ mcast_query_interval QUERY_INTERVAL ]\n"
		"\n"
		"Where: VLAN_PROTOCOL := { 802.1Q | 802.1ad }\n"
	);
}

static void explain(void)
{
	print_explain(stderr);
}

static void br_dump_bridge_id(const struct ifla_bridge_id *id, char *buf,
			      size_t len)
{
	char eaddr[32];

	ether_ntoa_r((const struct ether_addr *)id->addr, eaddr);
	snprintf(buf, len, "%.2x%.2x.%s", id->prio[0], id->prio[1], eaddr);
}

static int bridge_parse_opt(struct link_util *lu, int argc, char **argv,
			    struct nlmsghdr *n)
{
	__u32 val;

	while (argc > 0) {
		if (matches(*argv, "forward_delay") == 0) {
			NEXT_ARG();
			if (get_u32(&val, *argv, 0))
				invarg("invalid forward_delay", *argv);

			addattr32(n, 1024, IFLA_BR_FORWARD_DELAY, val);
		} else if (matches(*argv, "hello_time") == 0) {
			NEXT_ARG();
			if (get_u32(&val, *argv, 0))
				invarg("invalid hello_time", *argv);

			addattr32(n, 1024, IFLA_BR_HELLO_TIME, val);
		} else if (matches(*argv, "max_age") == 0) {
			NEXT_ARG();
			if (get_u32(&val, *argv, 0))
				invarg("invalid max_age", *argv);

			addattr32(n, 1024, IFLA_BR_MAX_AGE, val);
		} else if (matches(*argv, "ageing_time") == 0) {
			NEXT_ARG();
			if (get_u32(&val, *argv, 0))
				invarg("invalid ageing_time", *argv);

			addattr32(n, 1024, IFLA_BR_AGEING_TIME, val);
		} else if (matches(*argv, "stp_state") == 0) {
			NEXT_ARG();
			if (get_u32(&val, *argv, 0))
				invarg("invalid stp_state", *argv);

			addattr32(n, 1024, IFLA_BR_STP_STATE, val);
		} else if (matches(*argv, "priority") == 0) {
			__u16 prio;

			NEXT_ARG();
			if (get_u16(&prio, *argv, 0))
				invarg("invalid priority", *argv);

			addattr16(n, 1024, IFLA_BR_PRIORITY, prio);
		} else if (matches(*argv, "vlan_filtering") == 0) {
			__u8 vlan_filter;

			NEXT_ARG();
			if (get_u8(&vlan_filter, *argv, 0)) {
				invarg("invalid vlan_filtering", *argv);
				return -1;
			}
			addattr8(n, 1024, IFLA_BR_VLAN_FILTERING, vlan_filter);
		} else if (matches(*argv, "vlan_protocol") == 0) {
			__u16 vlan_proto;

			NEXT_ARG();
			if (ll_proto_a2n(&vlan_proto, *argv)) {
				invarg("invalid vlan_protocol", *argv);
				return -1;
			}
			addattr16(n, 1024, IFLA_BR_VLAN_PROTOCOL, vlan_proto);
		} else if (matches(*argv, "group_fwd_mask") == 0) {
			__u16 fwd_mask;

			NEXT_ARG();
			if (get_u16(&fwd_mask, *argv, 0))
				invarg("invalid group_fwd_mask", *argv);

			addattr16(n, 1024, IFLA_BR_GROUP_FWD_MASK, fwd_mask);
		} else if (matches(*argv, "group_address") == 0) {
			char llabuf[32];
			int len;

			NEXT_ARG();
			len = ll_addr_a2n(llabuf, sizeof(llabuf), *argv);
			if (len < 0)
				return -1;
			addattr_l(n, 1024, IFLA_BR_GROUP_ADDR, llabuf, len);
		} else if (matches(*argv, "vlan_default_pvid") == 0) {
			__u16 default_pvid;

			NEXT_ARG();
			if (get_u16(&default_pvid, *argv, 0))
				invarg("invalid vlan_default_pvid", *argv);

			addattr16(n, 1024, IFLA_BR_VLAN_DEFAULT_PVID,
				  default_pvid);
		} else if (matches(*argv, "mcast_router") == 0) {
			__u8 mcast_router;

			NEXT_ARG();
			if (get_u8(&mcast_router, *argv, 0))
				invarg("invalid mcast_router", *argv);

			addattr8(n, 1024, IFLA_BR_MCAST_ROUTER, mcast_router);
		} else if (matches(*argv, "mcast_snooping") == 0) {
			__u8 mcast_snoop;

			NEXT_ARG();
			if (get_u8(&mcast_snoop, *argv, 0))
				invarg("invalid mcast_snooping", *argv);

			addattr8(n, 1024, IFLA_BR_MCAST_SNOOPING, mcast_snoop);
		} else if (matches(*argv, "mcast_query_use_ifaddr") == 0) {
			__u8 mcast_qui;

			NEXT_ARG();
			if (get_u8(&mcast_qui, *argv, 0))
				invarg("invalid mcast_query_use_ifaddr",
				       *argv);

			addattr8(n, 1024, IFLA_BR_MCAST_QUERY_USE_IFADDR,
				 mcast_qui);
		} else if (matches(*argv, "mcast_querier") == 0) {
			__u8 mcast_querier;

			NEXT_ARG();
			if (get_u8(&mcast_querier, *argv, 0))
				invarg("invalid mcast_querier", *argv);

			addattr8(n, 1024, IFLA_BR_MCAST_QUERIER, mcast_querier);
		} else if (matches(*argv, "mcast_hash_elasticity") == 0) {
			__u32 mcast_hash_el;

			NEXT_ARG();
			if (get_u32(&mcast_hash_el, *argv, 0))
				invarg("invalid mcast_hash_elasticity",
				       *argv);

			addattr32(n, 1024, IFLA_BR_MCAST_HASH_ELASTICITY,
				  mcast_hash_el);
		} else if (matches(*argv, "mcast_hash_max") == 0) {
			__u32 mcast_hash_max;

			NEXT_ARG();
			if (get_u32(&mcast_hash_max, *argv, 0))
				invarg("invalid mcast_hash_max", *argv);

			addattr32(n, 1024, IFLA_BR_MCAST_HASH_MAX,
				  mcast_hash_max);
		} else if (matches(*argv, "mcast_last_member_count") == 0) {
			__u32 mcast_lmc;

			NEXT_ARG();
			if (get_u32(&mcast_lmc, *argv, 0))
				invarg("invalid mcast_last_member_count",
				       *argv);

			addattr32(n, 1024, IFLA_BR_MCAST_LAST_MEMBER_CNT,
				  mcast_lmc);
		} else if (matches(*argv, "mcast_startup_query_count") == 0) {
			__u32 mcast_sqc;

			NEXT_ARG();
			if (get_u32(&mcast_sqc, *argv, 0))
				invarg("invalid mcast_startup_query_count",
				       *argv);

			addattr32(n, 1024, IFLA_BR_MCAST_STARTUP_QUERY_CNT,
				  mcast_sqc);
		} else if (matches(*argv, "mcast_last_member_interval") == 0) {
			__u64 mcast_last_member_intvl;

			NEXT_ARG();
			if (get_u64(&mcast_last_member_intvl, *argv, 0))
				invarg("invalid mcast_last_member_interval",
				       *argv);

			addattr64(n, 1024, IFLA_BR_MCAST_LAST_MEMBER_INTVL,
				  mcast_last_member_intvl);
		} else if (matches(*argv, "mcast_membership_interval") == 0) {
			__u64 mcast_membership_intvl;

			NEXT_ARG();
			if (get_u64(&mcast_membership_intvl, *argv, 0)) {
				invarg("invalid mcast_membership_interval",
				       *argv);
				return -1;
			}
			addattr64(n, 1024, IFLA_BR_MCAST_MEMBERSHIP_INTVL,
				  mcast_membership_intvl);
		} else if (matches(*argv, "mcast_querier_interval") == 0) {
			__u64 mcast_querier_intvl;

			NEXT_ARG();
			if (get_u64(&mcast_querier_intvl, *argv, 0)) {
				invarg("invalid mcast_querier_interval",
				       *argv);
				return -1;
			}
			addattr64(n, 1024, IFLA_BR_MCAST_QUERIER_INTVL,
				  mcast_querier_intvl);
		} else if (matches(*argv, "mcast_query_interval") == 0) {
			__u64 mcast_query_intvl;

			NEXT_ARG();
			if (get_u64(&mcast_query_intvl, *argv, 0)) {
				invarg("invalid mcast_query_interval",
				       *argv);
				return -1;
			}
			addattr64(n, 1024, IFLA_BR_MCAST_QUERY_INTVL,
				  mcast_query_intvl);
		} else if (matches(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "bridge: unknown command \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--, argv++;
	}

	return 0;
}

static void bridge_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	if (!tb)
		return;

	if (tb[IFLA_BR_FORWARD_DELAY])
		fprintf(f, "forward_delay %u ",
			rta_getattr_u32(tb[IFLA_BR_FORWARD_DELAY]));

	if (tb[IFLA_BR_HELLO_TIME])
		fprintf(f, "hello_time %u ",
			rta_getattr_u32(tb[IFLA_BR_HELLO_TIME]));

	if (tb[IFLA_BR_MAX_AGE])
		fprintf(f, "max_age %u ",
			rta_getattr_u32(tb[IFLA_BR_MAX_AGE]));

	if (tb[IFLA_BR_AGEING_TIME])
		fprintf(f, "ageing_time %u ",
			rta_getattr_u32(tb[IFLA_BR_AGEING_TIME]));

	if (tb[IFLA_BR_STP_STATE])
		fprintf(f, "stp_state %u ",
			rta_getattr_u32(tb[IFLA_BR_STP_STATE]));

	if (tb[IFLA_BR_PRIORITY])
		fprintf(f, "priority %u ",
			rta_getattr_u16(tb[IFLA_BR_PRIORITY]));

	if (tb[IFLA_BR_VLAN_FILTERING])
		fprintf(f, "vlan_filtering %u ",
			rta_getattr_u8(tb[IFLA_BR_VLAN_FILTERING]));

	if (tb[IFLA_BR_VLAN_PROTOCOL]) {
		SPRINT_BUF(b1);

		fprintf(f, "vlan_protocol %s ",
			ll_proto_n2a(rta_getattr_u16(tb[IFLA_BR_VLAN_PROTOCOL]),
				     b1, sizeof(b1)));
	}

	if (tb[IFLA_BR_BRIDGE_ID]) {
		char bridge_id[32];

		br_dump_bridge_id(RTA_DATA(tb[IFLA_BR_BRIDGE_ID]), bridge_id,
				  sizeof(bridge_id));
		fprintf(f, "bridge_id %s ", bridge_id);
	}

	if (tb[IFLA_BR_ROOT_ID]) {
		char root_id[32];

		br_dump_bridge_id(RTA_DATA(tb[IFLA_BR_BRIDGE_ID]), root_id,
				  sizeof(root_id));
		fprintf(f, "designated_root %s ", root_id);
	}

	if (tb[IFLA_BR_ROOT_PORT])
		fprintf(f, "root_port %u ",
			rta_getattr_u16(tb[IFLA_BR_ROOT_PORT]));

	if (tb[IFLA_BR_ROOT_PATH_COST])
		fprintf(f, "root_path_cost %u ",
			rta_getattr_u32(tb[IFLA_BR_ROOT_PATH_COST]));

	if (tb[IFLA_BR_TOPOLOGY_CHANGE])
		fprintf(f, "topology_change %u ",
			rta_getattr_u8(tb[IFLA_BR_TOPOLOGY_CHANGE]));

	if (tb[IFLA_BR_TOPOLOGY_CHANGE_DETECTED])
		fprintf(f, "topology_change_detected %u ",
			rta_getattr_u8(tb[IFLA_BR_TOPOLOGY_CHANGE_DETECTED]));

	if (tb[IFLA_BR_HELLO_TIMER]) {
		struct timeval tv;

		__jiffies_to_tv(&tv, rta_getattr_u64(tb[IFLA_BR_HELLO_TIMER]));
		fprintf(f, "hello_timer %4i.%.2i ", (int)tv.tv_sec,
			(int)tv.tv_usec/10000);
	}

	if (tb[IFLA_BR_TCN_TIMER]) {
		struct timeval tv;

		__jiffies_to_tv(&tv, rta_getattr_u64(tb[IFLA_BR_TCN_TIMER]));
		fprintf(f, "tcn_timer %4i.%.2i ", (int)tv.tv_sec,
			(int)tv.tv_usec/10000);
	}

	if (tb[IFLA_BR_TOPOLOGY_CHANGE_TIMER]) {
		unsigned long jiffies;
		struct timeval tv;

		jiffies = rta_getattr_u64(tb[IFLA_BR_TOPOLOGY_CHANGE_TIMER]);
		__jiffies_to_tv(&tv, jiffies);
		fprintf(f, "topology_change_timer %4i.%.2i ", (int)tv.tv_sec,
			(int)tv.tv_usec/10000);
	}

	if (tb[IFLA_BR_GC_TIMER]) {
		struct timeval tv;

		__jiffies_to_tv(&tv, rta_getattr_u64(tb[IFLA_BR_GC_TIMER]));
		fprintf(f, "gc_timer %4i.%.2i ", (int)tv.tv_sec,
			(int)tv.tv_usec/10000);
	}

	if (tb[IFLA_BR_VLAN_DEFAULT_PVID])
		fprintf(f, "vlan_default_pvid %u ",
			rta_getattr_u16(tb[IFLA_BR_VLAN_DEFAULT_PVID]));

	if (tb[IFLA_BR_GROUP_FWD_MASK])
		fprintf(f, "group_fwd_mask %#x ",
			rta_getattr_u16(tb[IFLA_BR_GROUP_FWD_MASK]));

	if (tb[IFLA_BR_GROUP_ADDR]) {
		SPRINT_BUF(mac);

		fprintf(f, "group_address %s ",
			ll_addr_n2a(RTA_DATA(tb[IFLA_BR_GROUP_ADDR]),
				    RTA_PAYLOAD(tb[IFLA_BR_GROUP_ADDR]),
				    1 /*ARPHDR_ETHER*/, mac, sizeof(mac)));
	}

	if (tb[IFLA_BR_MCAST_SNOOPING])
		fprintf(f, "mcast_snooping %u ",
			rta_getattr_u8(tb[IFLA_BR_MCAST_SNOOPING]));

	if (tb[IFLA_BR_MCAST_ROUTER])
		fprintf(f, "mcast_router %u ",
			rta_getattr_u8(tb[IFLA_BR_MCAST_ROUTER]));

	if (tb[IFLA_BR_MCAST_QUERY_USE_IFADDR])
		fprintf(f, "mcast_query_use_ifaddr %u ",
			rta_getattr_u8(tb[IFLA_BR_MCAST_QUERY_USE_IFADDR]));

	if (tb[IFLA_BR_MCAST_QUERIER])
		fprintf(f, "mcast_querier %u ",
			rta_getattr_u8(tb[IFLA_BR_MCAST_QUERIER]));

	if (tb[IFLA_BR_MCAST_HASH_ELASTICITY])
		fprintf(f, "mcast_hash_elasticity %u ",
			rta_getattr_u32(tb[IFLA_BR_MCAST_HASH_ELASTICITY]));

	if (tb[IFLA_BR_MCAST_HASH_MAX])
		fprintf(f, "mcast_hash_max %u ",
			rta_getattr_u32(tb[IFLA_BR_MCAST_HASH_MAX]));

	if (tb[IFLA_BR_MCAST_LAST_MEMBER_CNT])
		fprintf(f, "mcast_last_member_count %u ",
			rta_getattr_u32(tb[IFLA_BR_MCAST_LAST_MEMBER_CNT]));

	if (tb[IFLA_BR_MCAST_STARTUP_QUERY_CNT])
		fprintf(f, "mcast_startup_query_count %u ",
			rta_getattr_u32(tb[IFLA_BR_MCAST_STARTUP_QUERY_CNT]));

	if (tb[IFLA_BR_MCAST_LAST_MEMBER_INTVL])
		fprintf(f, "mcast_last_member_interval %llu ",
			rta_getattr_u64(tb[IFLA_BR_MCAST_LAST_MEMBER_INTVL]));

	if (tb[IFLA_BR_MCAST_MEMBERSHIP_INTVL])
		fprintf(f, "mcast_membership_interval %llu ",
			rta_getattr_u64(tb[IFLA_BR_MCAST_MEMBERSHIP_INTVL]));

	if (tb[IFLA_BR_MCAST_QUERIER_INTVL])
		fprintf(f, "mcast_querier_interval %llu ",
			rta_getattr_u64(tb[IFLA_BR_MCAST_QUERIER_INTVL]));

	if (tb[IFLA_BR_MCAST_QUERY_INTVL])
		fprintf(f, "mcast_query_interval %llu ",
			rta_getattr_u64(tb[IFLA_BR_MCAST_QUERY_INTVL]));
}

static void bridge_print_help(struct link_util *lu, int argc, char **argv,
		FILE *f)
{
	print_explain(f);
}

struct link_util bridge_link_util = {
	.id		= "bridge",
	.maxattr	= IFLA_BR_MAX,
	.parse_opt	= bridge_parse_opt,
	.print_opt	= bridge_print_opt,
	.print_help     = bridge_print_help,
};
