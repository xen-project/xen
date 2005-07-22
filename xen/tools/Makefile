
include $(BASEDIR)/../Config.mk

default:
	$(MAKE) -C figlet
	$(MAKE) symbols

clean:
	$(MAKE) -C figlet clean
	rm -f *.o symbols

symbols: symbols.c
	$(HOSTCC) -o $@ $<
