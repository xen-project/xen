
include $(XEN_ROOT)/Config.mk

.PHONY: default
default: symbols fixdep

.PHONY: clean
clean:
	rm -f *.o symbols fixdep

symbols: symbols.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

fixdep: fixdep.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<
