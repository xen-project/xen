
include $(BASEDIR)/../Config.mk

figlet: figlet.c
	$(HOSTCC) -o $@ $<

.PHONY: clean
clean:
	rm -f *.o figlet
