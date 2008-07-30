XEN_ROOT = ../../../../..
include $(XEN_ROOT)/tools/firmware/Rules.mk

TARGET  = tcgbiosext.o
FILES   = tcgbios tpm_drivers
OBJECTS = $(foreach f,$(FILES),$(f).o)

CFLAGS += $(CFLAGS_include) -I.. -I../.. -DGCC_PROTOS

.PHONY: all clean

all: $(TARGET)

clean:
	rm -rf *.o $(TARGET)

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS_DIRECT) -r $^ -o $@
