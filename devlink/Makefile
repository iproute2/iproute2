include ../config.mk

ifeq ($(HAVE_MNL),y)

DEVLINKOBJ = devlink.o mnlg.o
TARGETS=devlink

CFLAGS += $(shell $(PKG_CONFIG) libmnl --cflags)
LDLIBS += $(shell $(PKG_CONFIG) libmnl --libs)

endif

all: $(TARGETS) $(LIBS)

devlink: $(DEVLINKOBJ)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

install: all
	install -m 0755 $(TARGETS) $(DESTDIR)$(SBINDIR)

clean:
	rm -f $(DEVLINKOBJ) $(TARGETS)
