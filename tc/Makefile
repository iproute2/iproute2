TCOBJ= tc.o tc_qdisc.o tc_class.o tc_filter.o tc_util.o \
       tc_monitor.o m_police.o m_estimator.o m_action.o \
       m_ematch.o emp_ematch.yacc.o emp_ematch.lex.o

include ../Config

TCMODULES :=
TCMODULES += q_fifo.o
TCMODULES += q_sfq.o
TCMODULES += q_red.o
TCMODULES += q_prio.o
TCMODULES += q_tbf.o
TCMODULES += q_cbq.o
TCMODULES += q_rr.o
TCMODULES += q_multiq.o
TCMODULES += q_netem.o
TCMODULES += f_rsvp.o
TCMODULES += f_u32.o
TCMODULES += f_route.o
TCMODULES += f_fw.o
TCMODULES += f_basic.o
TCMODULES += f_flow.o
TCMODULES += f_cgroup.o
TCMODULES += q_dsmark.o
TCMODULES += q_gred.o
TCMODULES += f_tcindex.o
TCMODULES += q_ingress.o
TCMODULES += q_hfsc.o
TCMODULES += q_htb.o
TCMODULES += q_drr.o
TCMODULES += m_gact.o
TCMODULES += m_mirred.o
TCMODULES += m_nat.o
TCMODULES += m_pedit.o
TCMODULES += m_skbedit.o
TCMODULES += p_ip.o
TCMODULES += p_icmp.o
TCMODULES += p_tcp.o
TCMODULES += p_udp.o
TCMODULES += em_nbyte.o
TCMODULES += em_cmp.o
TCMODULES += em_u32.o
TCMODULES += em_meta.o


ifeq ($(TC_CONFIG_XT),y)
  TCMODULES += m_xt.o
  LDLIBS += -lxtables
else
  ifeq ($(TC_CONFIG_XT_H),y)
	CFLAGS += -DTC_CONFIG_XT_H
	TCMODULES += m_xt.o
	LDLIBS += -lxtables
  else
  TCMODULES += m_ipt.o
  endif
endif

TCOBJ += $(TCMODULES)
LDLIBS += -L. -ltc -lm -ldl

TCLIB := tc_core.o
TCLIB += tc_red.o
TCLIB += tc_cbq.o
TCLIB += tc_estimator.o
TCLIB += tc_stab.o

CFLAGS += -DCONFIG_GACT -DCONFIG_GACT_PROB

TCSO :=
ifeq ($(TC_CONFIG_ATM),y)
  TCSO += q_atm.so
endif


LDFLAGS += -Wl,-export-dynamic

YACC := bison
LEX := flex

%.so: %.c
	$(CC) $(CFLAGS) -shared -fpic $< -o $@


all: libtc.a tc $(TCSO)

tc: $(TCOBJ) $(LIBNETLINK) $(LIBUTIL) $(TCLIB)

libtc.a: $(TCLIB)
	$(AR) rcs $@ $(TCLIB)

install: all
	mkdir -p $(DESTDIR)$(LIBDIR)/tc
	install -m 0755 tc $(DESTDIR)$(SBINDIR)
	for i in $(TCSO); \
	do install -m 755 $$i $(DESTDIR)$(LIBDIR)/tc; \
	done

clean:
	rm -f $(TCOBJ) $(TCLIB) libtc.a tc *.so emp_ematch.yacc.h; \
	rm -f emp_ematch.yacc.output

q_atm.so: q_atm.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fpic -o q_atm.so q_atm.c -latm

%.yacc.c: %.y
	$(YACC) $(YACCFLAGS) -o $@ $<

%.lex.c: %.l
	$(LEX) $(LEXFLAGS) -o$@ $<
