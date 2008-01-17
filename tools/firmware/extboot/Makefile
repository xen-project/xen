
override XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../../..
CFLAGS := -I$(XEN_ROOT)/tools/libxc -I.
include $(XEN_ROOT)/tools/Rules.mk

# Disable PIE/SSP if GCC supports them. They can break us.
CFLAGS  += $(call cc-option,$(CC),-nopie,)
CFLAGS  += $(call cc-option,$(CC),-fno-stack-protector,)
CFLAGS  += $(call cc-option,$(CC),-fno-stack-protector-all,)

CFLAGS  += -fno-builtin -O2 -msoft-float

.PHONY: all
all: extboot.bin

%.o: %.S
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

extboot.img: extboot.o
	$(LD) $(LDFLAGS_DIRECT) --oformat binary -Ttext 0 -o $@ $<

extboot.bin: extboot.img signrom
	./signrom extboot.img extboot.bin

signrom: signrom.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $^

clean:
	$(RM) -f *.o *.img *.bin signrom *~
