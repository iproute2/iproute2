# SPDX-License-Identifier: GPL-2.0
CFLAGS=
LDLIBS=
include ../../config.mk
ifeq ($(HAVE_CAP),y)
LDLIBS+= -lcap
endif

generate_nlmsg: generate_nlmsg.c ../../lib/libnetlink.a ../../lib/libutil.a
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -I../../include -I../../include/uapi -include../../include/uapi/linux/netlink.h -o $@ $^ -lmnl $(LDLIBS)

clean:
	rm -f generate_nlmsg
