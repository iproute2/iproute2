# SPDX-License-Identifier: GPL-2.0
include ../../config.mk

generate_nlmsg: generate_nlmsg.c ../../lib/libnetlink.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDLIBS) $(EXTRA_CFLAGS) -I../../include -include../../include/uapi/linux/netlink.h -o $@ $^ -lmnl

clean:
	rm -f generate_nlmsg
