GENLOBJ=genl.o

include ../Config

GENLMODULES :=
GENLMODULES += ctrl.o

GENLOBJ += $(GENLMODULES)

GENLLIB :=

LDFLAGS += -Wl,-export-dynamic
LDLIBS  += -lm -ldl

all: genl

genl: $(GENLOBJ) $(LIBNETLINK) $(LIBUTIL) $(GENLLIB)

install: all
	install -m 0755 genl $(DESTDIR)$(SBINDIR)

clean:
	rm -f $(GENLOBJ) $(GENLLIB) genl
