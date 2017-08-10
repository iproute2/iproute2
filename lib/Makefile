include ../Config

ifeq ($(IP_CONFIG_SETNS),y)
	CFLAGS += -DHAVE_SETNS
endif

ifeq ($(HAVE_ELF),y)
	CFLAGS += -DHAVE_ELF
endif

ifeq ($(HAVE_MNL),y)
	CFLAGS += -DHAVE_LIBMNL $(shell $(PKG_CONFIG) libmnl --cflags)
endif

CFLAGS += -fPIC

UTILOBJ = utils.o rt_names.o ll_types.o ll_proto.o ll_addr.o \
	inet_proto.o namespace.o json_writer.o \
	names.o color.o bpf.o exec.o fs.o

NLOBJ=libgenl.o ll_map.o libnetlink.o

all: libnetlink.a libutil.a

libnetlink.a: $(NLOBJ)
	$(QUIET_AR)$(AR) rcs $@ $^

libutil.a: $(UTILOBJ) $(ADDLIB)
	$(QUIET_AR)$(AR) rcs $@ $^

install:

clean:
	rm -f $(NLOBJ) $(UTILOBJ) $(ADDLIB) libnetlink.a libutil.a
