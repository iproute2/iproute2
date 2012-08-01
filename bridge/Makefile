BROBJ = bridge.o fdb.o monitor.o link.o

include ../Config

all: bridge

bridge: $(BROBJ) $(LIBNETLINK) 

install: all
	install -m 0755 br $(DESTDIR)$(SBINDIR)

clean:
	rm -f $(BROBJ) br

