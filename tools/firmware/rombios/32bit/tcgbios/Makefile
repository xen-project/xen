XEN_ROOT = $(CURDIR)/../../../../..
include $(XEN_ROOT)/tools/firmware/Rules.mk

TARGET  = tcgbiosext.o

CFLAGS += $(CFLAGS_xeninclude) -I.. -I../..

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	rm -rf *.o $(TARGET) $(DEPS)

.PHONY: distclean
distclean: clean

$(TARGET): tcgbios.o tpm_drivers.o
	$(LD) $(LDFLAGS_DIRECT) -r $^ -o $@

-include $(DEPS)
