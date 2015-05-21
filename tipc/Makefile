TIPCOBJ=bearer.o \
    cmdl.o link.o \
    media.o misc.o \
    msg.o nametable.o \
    node.o socket.o \
    tipc.o

TARGETS=tipc
LDLIBS += -lmnl

all: $(TARGETS) $(LIBS)

tipc: $(TIPCOBJ)

install: all
	install -m 0755 $(TARGETS) $(DESTDIR)$(SBINDIR)

clean:
	rm -f $(TIPCOBJ) $(TARGETS)
