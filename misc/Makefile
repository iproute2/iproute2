SSOBJ=ss.o ssfilter.o
NSTATOBJ=nstat.o
IFSTATOBJ=ifstat.o
RTACCTOBJ=rtacct.o
ARPDOBJ=arpd.o
RTSTATOBJ=rtstat.o

ALLOBJ=$(SSOBJ) $(NSTATOBJ) $(IFSTATOBJ) $(RTACCTOBJ) $(ARPDOBJ) $(RTSTATOBJ)
TARGETS=ss nstat ifstat rtacct arpd rtstat

all: $(TARGETS)

ss: $(SSOBJ) $(LIBUTIL)

nstat: $(NSTATOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o nstat $(NSTATOBJ) -lm

ifstat: $(IFSTATOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o ifstat $(IFSTATOBJ) $(LIBNETLINK) -lm

rtacct: $(RTACCTOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o rtacct $(RTACCTOBJ) $(LIBNETLINK) -lm

arpd: $(ARPDOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o arpd $(ARPDOBJ) $(LIBNETLINK) -ldb

rtstat: $(RTSTATOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o rtstat $(RTSTATOBJ)

ssfilter.c: ssfilter.y
	bison ssfilter.y -o ssfilter.c

install: all 
	install -m 0755 -s $(TARGETS) $(DESTDIR)$(SBINDIR)

clean:
	rm -f $(ALLOBJ) $(TARGETS) ssfilter.c
