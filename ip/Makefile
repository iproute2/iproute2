IPOBJ=ip.o ipaddress.o iproute.o iprule.o \
    rtm_map.o iptunnel.o ipneigh.o iplink.o \
    ipmaddr.o ipmonitor.o ipmroute.o 

include ../Config

ifeq ($(IP_CONFIG_XFRM),y)
	IPOBJ   += ipxfrm.o xfrm_state.o xfrm_policy.o
else
	IPOBJ	+= xfrm_stub.o
endif

RTMONOBJ=rtmon.o

ALLOBJ=$(IPOBJ) $(RTMONOBJ)
TARGETS=ip rtmon

all: $(TARGETS)

ip: $(IPOBJ) $(LIBNETLINK) $(LIBUTIL)

rtmon: $(RTMONOBJ) $(LIBNETLINK)

install: all
	install -m 0755 -s $(TARGETS) $(DESTDIR)$(SBINDIR)
	install -m 0755 routel routef $(DESTDIR)$(SBINDIR)

clean:
	rm -f $(ALLOBJ) $(TARGETS)

