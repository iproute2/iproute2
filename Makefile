# Path to parent kernel include files directory
DESTDIR=
SBINDIR=/usr/sbin
CONFDIR=/etc/iproute2
DOCDIR=/usr/doc/iproute2

KERNEL_INCLUDE=/usr/include
LIBC_INCLUDE=/usr/include

DEFINES= -DRESOLVE_HOSTNAMES

#options if you have a bind>=4.9.4 libresolv (or, maybe, glibc)
LDLIBS=-lresolv
ADDLIB=

#options if you compile with libc5, and without a bind>=4.9.4 libresolv
#LDLIBS=
#ADDLIB=inet_ntop.o inet_pton.o

#options for decnet
ADDLIB+=dnet_ntop.o dnet_pton.o

#options for ipx
ADDLIB+=ipx_ntop.o ipx_pton.o

CC = gcc
CCOPTS = -D_GNU_SOURCE -O2 -Wstrict-prototypes -Wall -g
CFLAGS = $(CCOPTS) -I$(KERNEL_INCLUDE) -I../include -I/usr/include/db41 $(DEFINES)

LDLIBS += -L../lib -lnetlink -lutil

SUBDIRS=lib ip tc misc

LIBNETLINK=../lib/libnetlink.a ../lib/libutil.a

all:
	for i in $(SUBDIRS); \
	do $(MAKE) -C $$i; done

install: all
	install -m 0755 -d $(DESTDIR)$(SBINDIR)
	install -m 0755 -d $(DESTDIR)$(CONFDIR)
	install -m 0755 -d $(DESTDIR)$(DOCDIR)/examples
	install -m 0755 -d $(DESTDIR)$(DOCDIR)/examples/diffserv
	install -m 0644 README.iproute2+tc $(shell find examples -type f -maxdepth 1) $(DESTDIR)$(DOCDIR)/examples
	install -m 0644 $(shell echo examples/diffserv/*) $(DESTDIR)$(DOCDIR)/examples/diffserv
	@for i in $(SUBDIRS) doc; do $(MAKE) -C $$i install; done
	@cd etc/iproute2; for i in *; do \
		if [ ! -e $(DESTDIR)$(CONFDIR)/$$i ]; then \
			echo install -m 0644 $$i $(DESTDIR)$(CONFDIR); \
			install -m 0644 $$i $(DESTDIR)$(CONFDIR); fi; done

clean:
	for i in $(SUBDIRS) doc; \
	do $(MAKE) -C $$i clean; done

.EXPORT_ALL_VARIABLES:
