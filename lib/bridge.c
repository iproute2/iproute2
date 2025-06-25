// SPDX-License-Identifier: GPL-2.0

#include <net/if.h>

#include "bridge.h"
#include "utils.h"

void bridge_print_vlan_flags(__u16 flags)
{
	if (flags == 0)
		return;

	open_json_array(PRINT_JSON, "flags");
	if (flags & BRIDGE_VLAN_INFO_PVID)
		print_string(PRINT_ANY, NULL, " %s", "PVID");

	if (flags & BRIDGE_VLAN_INFO_UNTAGGED)
		print_string(PRINT_ANY, NULL, " %s", "Egress Untagged");
	close_json_array(PRINT_JSON, NULL);
}

void bridge_print_vlan_stats_only(const struct bridge_vlan_xstats *vstats)
{
	print_string(PRINT_FP, NULL, "%-" textify(IFNAMSIZ) "s    ", "");
	print_lluint(PRINT_ANY, "rx_bytes", "RX: %llu bytes",
		     vstats->rx_bytes);
	print_lluint(PRINT_ANY, "rx_packets", " %llu packets\n",
		     vstats->rx_packets);

	print_string(PRINT_FP, NULL, "%-" textify(IFNAMSIZ) "s    ", "");
	print_lluint(PRINT_ANY, "tx_bytes", "TX: %llu bytes",
		     vstats->tx_bytes);
	print_lluint(PRINT_ANY, "tx_packets", " %llu packets\n",
		     vstats->tx_packets);
}

void bridge_print_vlan_stats(const struct bridge_vlan_xstats *vstats)
{
	open_json_object(NULL);

	print_hu(PRINT_ANY, "vid", "%hu", vstats->vid);
	bridge_print_vlan_flags(vstats->flags);
	print_nl();
	bridge_print_vlan_stats_only(vstats);

	close_json_object();
}

void bridge_print_mcast_querier_state(const struct rtattr *vtb)
{
	struct rtattr *bqtb[BRIDGE_QUERIER_MAX + 1];
	const char *querier_ip;
	SPRINT_BUF(other_time);
	__u64 tval;

	parse_rtattr_nested(bqtb, BRIDGE_QUERIER_MAX, vtb);
	memset(other_time, 0, sizeof(other_time));

	open_json_object("mcast_querier_state_ipv4");
	if (bqtb[BRIDGE_QUERIER_IP_ADDRESS]) {
		querier_ip = format_host_rta(AF_INET,
					     bqtb[BRIDGE_QUERIER_IP_ADDRESS]);
		print_string(PRINT_FP, NULL, "%s ",
			     "mcast_querier_ipv4_addr");
		print_color_string(PRINT_ANY, COLOR_INET,
				   "mcast_querier_ipv4_addr", "%s ",
				   querier_ip);
	}
	if (bqtb[BRIDGE_QUERIER_IP_PORT])
		print_uint(PRINT_ANY, "mcast_querier_ipv4_port",
			   "mcast_querier_ipv4_port %u ",
			   rta_getattr_u32(bqtb[BRIDGE_QUERIER_IP_PORT]));
	if (bqtb[BRIDGE_QUERIER_IP_OTHER_TIMER]) {
		tval = rta_getattr_u64(bqtb[BRIDGE_QUERIER_IP_OTHER_TIMER]);
		print_string(PRINT_ANY,
			     "mcast_querier_ipv4_other_timer",
			     "mcast_querier_ipv4_other_timer %s ",
			     sprint_time64(tval, other_time));
	}
	close_json_object();
	open_json_object("mcast_querier_state_ipv6");
	if (bqtb[BRIDGE_QUERIER_IPV6_ADDRESS]) {
		querier_ip = format_host_rta(AF_INET6,
					     bqtb[BRIDGE_QUERIER_IPV6_ADDRESS]);
		print_string(PRINT_FP, NULL, "%s ",
			     "mcast_querier_ipv6_addr");
		print_color_string(PRINT_ANY, COLOR_INET6,
				   "mcast_querier_ipv6_addr", "%s ",
				   querier_ip);
	}
	if (bqtb[BRIDGE_QUERIER_IPV6_PORT])
		print_uint(PRINT_ANY, "mcast_querier_ipv6_port",
			   "mcast_querier_ipv6_port %u ",
			   rta_getattr_u32(bqtb[BRIDGE_QUERIER_IPV6_PORT]));
	if (bqtb[BRIDGE_QUERIER_IPV6_OTHER_TIMER]) {
		tval = rta_getattr_u64(bqtb[BRIDGE_QUERIER_IPV6_OTHER_TIMER]);
		print_string(PRINT_ANY,
			     "mcast_querier_ipv6_other_timer",
			     "mcast_querier_ipv6_other_timer %s ",
			     sprint_time64(tval, other_time));
	}
	close_json_object();
}
