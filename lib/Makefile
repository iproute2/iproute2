# SPDX-License-Identifier: GPL-2.0
include ../config.mk

CFLAGS += -fPIC

UTILOBJ = utils.o rt_names.o ll_map.o ll_types.o ll_proto.o ll_addr.o \
	inet_proto.o namespace.o json_writer.o json_print.o \
	names.o color.o bpf.o exec.o fs.o

NLOBJ=libgenl.o libnetlink.o

all: libnetlink.a libutil.a

libnetlink.a: $(NLOBJ)
	$(QUIET_AR)$(AR) rcs $@ $^

libutil.a: $(UTILOBJ) $(ADDLIB)
	$(QUIET_AR)$(AR) rcs $@ $^

install:

clean:
	rm -f $(NLOBJ) $(UTILOBJ) $(ADDLIB) libnetlink.a libutil.a
