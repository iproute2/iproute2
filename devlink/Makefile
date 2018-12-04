# SPDX-License-Identifier: GPL-2.0
include ../config.mk

TARGETS :=

ifeq ($(HAVE_MNL),y)

DEVLINKOBJ = devlink.o mnlg.o
TARGETS += devlink

endif

all: $(TARGETS) $(LIBS)

devlink: $(DEVLINKOBJ)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

install: all
	install -m 0755 $(TARGETS) $(DESTDIR)$(SBINDIR)

clean:
	rm -f $(DEVLINKOBJ) $(TARGETS)
