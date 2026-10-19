#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

. lib/generic.sh

# suffix|description|expected regex (leading ! = must not match)
while IFS='|' read -r suffix desc expect; do
	[ -z "$suffix" ] && continue
	NL_FILE="tests/ip/link/bond_slave_partner_${suffix}.nl"
	ts_ip "$0" "$desc" -d monitor file "$NL_FILE"
	case "$expect" in
	!*)
		test_on "ad_actor_oper_port_state 63[^0-9]"
		test_on_not "${expect#!}"
		;;
	*)
		test_on "$expect"
		;;
	esac
done <<EOF
fast|partner state 0x3f|ad_partner_oper_port_state 63 ad_partner_oper_port_state_str <active,short_timeout,aggregating,in_sync,collecting,distributing>
fast|actor state stays u8|ad_actor_oper_port_state 63[^0-9]
zero|partner state 0|ad_partner_oper_port_state 0 ad_partner_oper_port_state_str <>
hionly|partner state 0x0100, high byte only|ad_partner_oper_port_state 256[^0-9]
absent|no partner attribute|!ad_partner_oper_port_state
EOF
