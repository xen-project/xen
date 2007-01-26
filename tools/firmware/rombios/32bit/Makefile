
override XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../../../..
CFLAGS :=
include $(XEN_ROOT)/tools/Rules.mk

TARGET = 32bitbios_flat.h

CFLAGS += -fno-builtin -O2 -msoft-float
CFLAGS += -I../

MODULES = 32bitbios.o

.PHONY: all

all : $(TARGET)

clean ::
	rm -rf *.o $(TARGET)

$(TARGET) : 32bitbios_all.o $(SOURCES)
	unref=`nm -u 32bitbios_all.o`
	@if [ "$$unref" != "" ]; then \
		echo "There are unresolved symbols in the BIOS.";	\
		echo $$unref ;						\
	else								\
		bash mkhex highbios_array 32bitbios_all.o > $(TARGET); \
	fi

32bitbios_all.o : 32bitbios.o $(MODULES)
	ld $(LDFLAGS_DIRECT) -r $(MODULES) -o 32bitbios_all.o
