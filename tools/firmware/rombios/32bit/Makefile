
override XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../../../..
CFLAGS :=
include $(XEN_ROOT)/tools/Rules.mk

SOURCES = util.c
TARGET = 32bitbios_flat.h

CFLAGS += -fno-builtin -O2 -msoft-float -nostdlib
CFLAGS += -I../

SUBDIRS = tcgbios

MODULES := 32bitbios.o
MODULES += tcgbios/tcgbiosext.o
MODULES += util.o

.PHONY: all subdirs

subdirs:
	@for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir all; \
	done;

all: subdirs $(TARGET)

clean::
	rm -rf *.o $(TARGET)
	@for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done;

$(TARGET): 32bitbios_all.o $(SOURCES)
	unref=`nm -u 32bitbios_all.o`
	@if [ "$$unref" != "" ]; then \
		echo "There are unresolved symbols in the BIOS.";	\
		echo $$unref ;						\
	else								\
		bash mkhex highbios_array 32bitbios_all.o > $(TARGET); \
	fi

32bitbios_all.o: $(MODULES)
	ld $(LDFLAGS_DIRECT) -r $(MODULES) -o 32bitbios_all.o
