include ../config.mk

ifeq ($(HAVE_MNL),y)

RDMA_OBJ = rdma.o utils.o dev.o link.o

TARGETS=rdma
endif

all:	$(TARGETS) $(LIBS)

rdma:	$(RDMA_OBJ) $(LIBS)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

install: all
	install -m 0755 $(TARGETS) $(DESTDIR)$(SBINDIR)

clean:
	rm -f $(RDMA_OBJ) $(TARGETS)
