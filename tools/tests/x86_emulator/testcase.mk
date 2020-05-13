XEN_ROOT = $(CURDIR)/../../..
CFLAGS :=
include $(XEN_ROOT)/tools/Rules.mk

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))

CFLAGS += -fno-builtin -g0 $($(TESTCASE)-cflags)

.PHONY: all
all: $(TESTCASE).bin

%.bin: %.c
	$(CC) $(filter-out -M% .%,$(CFLAGS)) -c $<
	$(LD) $(LDFLAGS_DIRECT) -N -Ttext 0x100000 -o $*.tmp $*.o
	$(OBJCOPY) -O binary $*.tmp $@
	rm -f $*.tmp

%-opmask.bin: opmask.S
	$(CC) $(filter-out -M% .%,$(CFLAGS)) -c $< -o $(basename $@).o
	$(LD) $(LDFLAGS_DIRECT) -N -Ttext 0x100000 -o $(basename $@).tmp $(basename $@).o
	$(OBJCOPY) -O binary $(basename $@).tmp $@
	rm -f $(basename $@).tmp
