XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS := 32bit

.PHONY: all
all: subdirs-all
	$(MAKE) BIOS-bochs-latest

.PHONY: clean
clean: subdirs-clean
	rm -f  *.o *.a *.s rombios.bin _rombios*_.c
	rm -f  as86-sym.txt ld86-sym.txt 
	rm -f  rombios*.txt rombios*.sym usage biossums
	rm -f  BIOS-bochs-*
	rm -f  $(DEPS)

BIOS-bochs-latest: rombios.c biossums 32bitgateway.c tcgbios.c
	gcc -DBX_SMP_PROCESSORS=1 -E -P $< > _rombios_.c
	bcc -o rombios.s -C-c -D__i86__ -0 -S _rombios_.c
	sed -e 's/^\.text//' -e 's/^\.data//' rombios.s > _rombios_.s
	as86 _rombios_.s -b tmp.bin -u- -w- -g -0 -j -O -l rombios.txt
	-perl makesym.perl < rombios.txt > rombios.sym
	mv tmp.bin BIOS-bochs-latest
	./biossums BIOS-bochs-latest
	rm -f _rombios_.s

biossums: biossums.c
	gcc -o biossums biossums.c

-include $(DEPS)
