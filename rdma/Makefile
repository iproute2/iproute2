include ../Config

ifeq ($(HAVE_MNL),y)

RDMA_OBJ = rdma.o utils.o dev.o link.o

TARGETS=rdma
CFLAGS += $(shell $(PKG_CONFIG) libmnl --cflags)
LDLIBS += $(shell $(PKG_CONFIG) libmnl --libs)

endif

all:	$(TARGETS) $(LIBS)

rdma:	$(RDMA_OBJ) $(LIBS)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

install: all
	install -m 0755 $(TARGETS) $(DESTDIR)$(SBINDIR)

clean:
	rm -f $(RDMA_OBJ) $(TARGETS)
