#!/bin/sh

. lib/generic.sh

ts_log "[Testing add/get neigh]"

NEW_DEV="$(rand_dev)"
ts_ip "$0" "Add $NEW_DEV dummy interface" link add dev $NEW_DEV type dummy
ts_ip "$0" "Add $NEW_DEV neighbor 192.0.2.2 " neigh add 192.0.2.2 lladdr 02:00:00:00:00:01 dev $NEW_DEV
ts_ip "$0" "List neighbors " neigh list
test_on '02:00:00:00:00:01'
ts_ip "$0" "Get $NEW_DEV neighbor 192.0.2.2 " --json neigh get 192.0.2.2 dev $NEW_DEV
test_on '"lladdr":"02:00:00:00:00:01"'
