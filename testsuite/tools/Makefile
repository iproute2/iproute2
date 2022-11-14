# SPDX-License-Identifier: GPL-2.0
CFLAGS=
include ../../config.mk

generate_nlmsg: generate_nlmsg.c ../../lib/libnetlink.a ../../lib/libutil.a
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -I../../include -I../../include/uapi -include../../include/uapi/linux/netlink.h -o $@ $^ -lmnl -lcap

clean:
	rm -f generate_nlmsg
