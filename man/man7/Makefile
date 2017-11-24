# SPDX-License-Identifier: GPL-2.0
MAN7PAGES = $(wildcard *.7)

all:

distclean: clean

clean:

install:
	$(INSTALLDIR) $(DESTDIR)$(MANDIR)/man7
	$(INSTALLMAN) $(MAN7PAGES) $(DESTDIR)$(MANDIR)/man7

.PHONY: install clean distclean
