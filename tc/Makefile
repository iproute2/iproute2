TCOBJ=tc.o tc_qdisc.o tc_class.o tc_filter.o tc_util.o m_police.o m_estimator.o

include ../Config

TCMODULES :=
TCMODULES += q_fifo.o
TCMODULES += q_sfq.o
TCMODULES += q_red.o
TCMODULES += q_prio.o
TCMODULES += q_tbf.o
TCMODULES += q_cbq.o
TCMODULES += f_rsvp.o
TCMODULES += f_u32.o
TCMODULES += f_route.o
TCMODULES += f_fw.o
TCMODULES += q_dsmark.o
TCMODULES += q_gred.o
TCMODULES += f_tcindex.o
TCMODULES += q_ingress.o

ifeq ($(TC_CONFIG_ATM),y)
  TCMODULES += q_atm.o
  LDLIBS += -latm
endif

TCMODULES += q_netem.o
TCMODULES += q_csz.o
TCMODULES += q_htb.o
TCMODULES += q_hpfq.o
TCMODULES += q_hfsc.o

TCOBJ += $(TCMODULES)

TCLIB := tc_core.o
TCLIB += tc_red.o
TCLIB += tc_cbq.o
TCLIB += tc_estimator.o

LDLIBS += -L. -ltc -lm -ldl
LDFLAGS += -Wl,-export-dynamic

all: libtc.a tc

tc: $(TCOBJ) $(LIBNETLINK) $(LIBUTIL) $(TCLIB)

libtc.a: $(TCLIB)
	$(AR) rcs $@ $(TCLIB)

install: all
	install -m 0755 -s tc $(DESTDIR)$(SBINDIR)


clean:
	rm -f $(TCOBJ) $(TCLIB) libtc.a tc

