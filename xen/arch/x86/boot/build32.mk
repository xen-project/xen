XEN_ROOT=../../../..
override XEN_TARGET_ARCH=x86_32
CFLAGS =
include $(XEN_ROOT)/Config.mk

# Disable PIE/SSP if GCC supports them. They can break us.
$(call cc-option-add,CFLAGS,CC,-nopie)
$(call cc-option-add,CFLAGS,CC,-fno-stack-protector)
$(call cc-option-add,CFLAGS,CC,-fno-stack-protector-all)

CFLAGS += -Werror -fno-builtin -msoft-float

%.S: %.bin
	(od -v -t x $< | head -n -1 | \
	sed 's/ /,0x/g' | sed 's/^[0-9]*,/ .long /') >$@

%.bin: %.lnk
	$(OBJCOPY) -O binary $< $@

%.lnk: %.o
	$(LD) $(LDFLAGS_DIRECT) -N -Ttext 0x8c000 -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
