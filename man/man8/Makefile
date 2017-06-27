TARGETS = ip-address.8 ip-link.8 ip-route.8

MAN8PAGES = $(TARGETS) $(filter-out $(TARGETS),$(wildcard *.8))

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
