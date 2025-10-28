# SPDX-License-Identifier: GPL-2.0
include ../config.mk

NSOBJ = netshaper.o
TARGETS += netshaper
LDLIBS += -lm

all: $(TARGETS) $(LIBS)

netshaper: $(NSOBJ)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

install: all
	for i in $(TARGETS); \
	do install -m 0755 $$i $(DESTDIR)$(SBINDIR); \
	done

clean:
	rm -f $(NSOBJ) $(TARGETS)
