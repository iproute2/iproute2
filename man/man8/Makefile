TARGETS = ip-address.8 ip-link.8 ip-route.8

MAN8PAGES = $(TARGETS) ip.8 arpd.8 lnstat.8 routel.8 rtacct.8 rtmon.8 ss.8 \
	tc-bfifo.8 tc-cbq-details.8 tc-cbq.8 tc-drr.8 tc-htb.8 \
	tc-pfifo.8 tc-pfifo_fast.8 tc-prio.8 tc-red.8 tc-sfq.8 \
	tc-tbf.8 tc.8 rtstat.8 ctstat.8 nstat.8 routef.8

all: $(TARGETS)

ip-address.8: ip-address.8.in
	sed "s|@SYSCONFDIR@|$(CONFDIR)|g" $< > $@

ip-link.8: ip-link.8.in
	sed "s|@SYSCONFDIR@|$(CONFDIR)|g" $< > $@

ip-route.8: ip-route.8.in
	sed "s|@SYSCONFDIR@|$(CONFDIR)|g" $< > $@

distclean: clean

clean:
	@rm -f $(TARGETS)

install:
	$(INSTALLDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALLMAN) $(MAN8PAGES) $(DESTDIR)$(MANDIR)/man8

.PHONY: install clean distclean
