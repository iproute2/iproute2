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
