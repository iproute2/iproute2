SSOBJ=ss.o ssfilter.o

TARGETS=ss nstat ifstat rtacct arpd rtstat

include ../Config

ifeq ($(SS_CONFIG_VEGAS),y)
	DEFINES += -DHAVE_TCP_VEGAS
endif
ifeq ($(SS_CONFIG_DRS),y)
	DEFINES += -DHAVE_TCP_DRS
endif

all: $(TARGETS)

ss: $(SSOBJ) $(LIBUTIL)

nstat: nstat.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o nstat nstat.c -lm

ifstat: ifstat.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o ifstat ifstat.c $(LIBNETLINK) -lm

rtacct: rtacct.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o rtacct rtacct.c $(LIBNETLINK) -lm

arpd: arpd.c
	$(CC) $(CFLAGS) -I$(DBM_INCLUDE) $(LDFLAGS) -o arpd arpd.c $(LIBNETLINK) -ldb

rtstat: rtstat.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o rtstat rtstat.c

ssfilter.c: ssfilter.y
	bison ssfilter.y -o ssfilter.c

install: all 
	install -m 0755 -s $(TARGETS) $(DESTDIR)$(SBINDIR)

clean:
	rm -f *.o $(TARGETS) ssfilter.c
