TESTS := $(patsubst tests/%,%,$(wildcard tests/*))
IPVERS := $(filter-out iproute2/Makefile,$(wildcard iproute2/*))

DEV := eth0

.PHONY: compile listtests alltests $(TESTS)

compile:
	echo "Entering iproute2" && cd iproute2 && $(MAKE) && cd ..;

listtests:
	@for t in $(TESTS); do \
		echo "$$t"; \
	done

alltests: $(TESTS)

clean:
	@rm -rf results/*

$(TESTS):
	@for i in $(IPVERS); do \
		echo -n "Running $@ with $$i on `uname -r`: "; \
		logger "TESTMARK: $@"; \
		o=`echo $$i | sed -e 's/iproute2\///'`; \
		TC="$$i/tc/tc" IP="$$i/ip/ip" DEV="$(DEV)" sudo tests/$@ > results/$@.$$o.out 2> results/$@.$$o.err; \
		dmesg > results/$@.$$o.dmesg; \
		if [ -z "`cat results/$@.$$o.err`" ]; then \
			echo "PASS"; \
		else \
			echo "FAILED"; \
		fi \
	done
