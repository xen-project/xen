XEN_ROOT=../../../..
override XEN_TARGET_ARCH=x86_32
CFLAGS =
include $(XEN_ROOT)/Config.mk

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))

CFLAGS += -Werror -fno-builtin -msoft-float

# NB. awk invocation is a portable alternative to 'head -n -1'
%.S: %.bin
	(od -v -t x $< | awk 'NR > 1 {print s} {s=$$0}' | \
	sed 's/ /,0x/g' | sed 's/^[0-9]*,/ .long /') >$@

%.bin: %.lnk
	$(OBJCOPY) -O binary $< $@

%.lnk: %.o
	$(LD) $(LDFLAGS_DIRECT) -N -Ttext $(RELOC) -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -DXEN_BITSPERLONG=$(XEN_BITSPERLONG) -c $< -o $@

reloc.o: $(BASEDIR)/include/asm-x86/config.h
