XEN_ROOT = $(CURDIR)/../../../../..
include $(XEN_ROOT)/tools/firmware/Rules.mk

TARGET  = tcgbiosext.o

CFLAGS += $(CFLAGS_xeninclude) -I.. -I../.. -I../../../../libacpi
$(call cc-option-add,CFLAGS,CC,-fno-pic)
$(call cc-option-add,CFLAGS,CC,-fno-PIE)

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
