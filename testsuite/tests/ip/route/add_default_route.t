#!/bin/sh

source lib/generic.sh

ts_log "[Testing add default route]"

DEV=dummy0

ts_ip "$0" "Add new interface $DEV" link add $DEV type dummy
ts_ip "$0" "Set $DEV into UP state" link set up dev $DEV
ts_ip "$0" "Add 1.1.1.1/24 addr on $DEV" addr add 1.1.1.1/24 dev $DEV
ts_ip "$0" "Add default route via 1.1.1.1" route add default via 1.1.1.1
