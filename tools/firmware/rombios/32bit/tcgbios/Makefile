
override XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../../../../..
CFLAGS :=
include $(XEN_ROOT)/tools/Rules.mk

TARGET  = tcgbiosext.o
FILES   = tcgbios tpm_drivers
OBJECTS = $(foreach f,$(FILES),$(f).o)

CFLAGS += -fno-builtin -O2 -msoft-float -nostdlib
CFLAGS += -I../ -I../../ -DGCC_PROTOS

.PHONY: all clean

all: $(TARGET)

clean:
	rm -rf *.o $(TARGET)

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS_DIRECT) -r $^ -o $@
