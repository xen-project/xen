
XEN_ROOT = $(BASEDIR)/..
include $(XEN_ROOT)/Config.mk

.PHONY: default
default:
	$(MAKE) -C figlet
	$(MAKE) symbols

.PHONY: clean
clean:
	$(MAKE) -C figlet clean
	rm -f *.o symbols

symbols: symbols.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<
