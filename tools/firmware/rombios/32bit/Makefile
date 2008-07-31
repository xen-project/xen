XEN_ROOT = ../../../..
include $(XEN_ROOT)/tools/firmware/Rules.mk

SOURCES = util.c
TARGET = 32bitbios_flat.h

CFLAGS += $(CFLAGS_include) -I.. -DGCC_PROTOS

SUBDIRS = tcgbios

MODULES = tcgbios/tcgbiosext.o

.PHONY: all
all: subdirs-all
	$(MAKE) $(TARGET)

.PHONY: clean
clean: subdirs-clean
	rm -rf *.o $(TARGET)

$(TARGET): 32bitbios.o $(MODULES) util.o
	$(LD) $(LDFLAGS_DIRECT) -s -r $^ -o 32bitbios_all.o
	@nm 32bitbios_all.o |                                \
	  egrep '^ +U ' >/dev/null && {                      \
	    echo "There are undefined symbols in the BIOS:"; \
	    nm -u 32bitbios_all.o;                           \
	    exit 11;                                         \
	  } || :
	sh mkhex highbios_array 32bitbios_all.o > $@
