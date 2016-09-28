XEN_ROOT = $(CURDIR)/../../../..
include $(XEN_ROOT)/tools/firmware/Rules.mk

TARGET = 32bitbios_flat.h

CFLAGS += $(CFLAGS_xeninclude) -I.. -I../../../libacpi

SUBDIRS = tcgbios

.PHONY: all
all: subdirs-all
	$(MAKE) $(TARGET)

.PHONY: clean
clean: subdirs-clean
	rm -rf *.o $(TARGET) $(DEPS)

.PHONY: distclean
distclean: subdirs-distclean

$(TARGET): 32bitbios_all.o
	sh mkhex highbios_array 32bitbios_all.o > $@

32bitbios_all.o: 32bitbios.o tcgbios/tcgbiosext.o util.o pmm.o
	$(LD) $(LDFLAGS_DIRECT) -s -r $^ -o 32bitbios_all.o
	@nm 32bitbios_all.o |                                \
	  egrep '^ +U ' >/dev/null && {                      \
	    echo "There are undefined symbols in the BIOS:"; \
	    nm -u 32bitbios_all.o;                           \
	    exit 11;                                         \
	  } || :

-include $(DEPS)
