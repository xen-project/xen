
include $(XEN_ROOT)/Config.mk

.PHONY: default
default:
	[ -d figlet ] && $(MAKE) -C figlet
	$(MAKE) symbols

.PHONY: clean
clean:
	[ -d figlet ] && $(MAKE) -C figlet clean
	rm -f *.o symbols

symbols: symbols.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<
