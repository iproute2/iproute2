#!/bin/sh

. lib/generic.sh

TUNNEL_NAME="tunnel_test_ip"

ts_log "[Testing add/del tunnels]"

ts_ip "$0" "Add GRE tunnel over IPv4" tunnel add name $TUNNEL_NAME mode gre local 1.1.1.1 remote 2.2.2.2
ts_ip "$0" "Del GRE tunnel over IPv4" tunnel del $TUNNEL_NAME

ts_ip "$0" "Add GRE tunnel over IPv6" tunnel add name $TUNNEL_NAME mode ip6gre local dead:beef::1 remote dead:beef::2
ts_ip "$0" "Del GRE tunnel over IPv6" tunnel del $TUNNEL_NAME

