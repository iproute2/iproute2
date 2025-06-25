/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BRIDGE_H__
#define __BRIDGE_H__ 1

#include <linux/if_bridge.h>
#include <linux/rtnetlink.h>

void bridge_print_vlan_flags(__u16 flags);
void bridge_print_vlan_stats_only(const struct bridge_vlan_xstats *vstats);
void bridge_print_vlan_stats(const struct bridge_vlan_xstats *vstats);

void bridge_print_mcast_querier_state(const struct rtattr *vtb);

#endif /* __BRIDGE_H__ */
