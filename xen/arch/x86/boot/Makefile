obj-bin-y += head.o

obj32 := cmdline.32.o
obj32 += reloc.32.o

nocov-y   += $(obj32)
noubsan-y += $(obj32)
targets   += $(obj32)

obj32 := $(addprefix $(obj)/,$(obj32))

$(obj)/head.o: AFLAGS-y += -Wa$(comma)-I$(obj)
$(obj)/head.o: $(obj32:.32.o=.bin)

CFLAGS_x86_32 := $(subst -m64,-m32 -march=i686,$(XEN_TREEWIDE_CFLAGS))
$(call cc-options-add,CFLAGS_x86_32,CC,$(EMBEDDED_EXTRA_CFLAGS))
CFLAGS_x86_32 += -Werror -fno-builtin -g0 -msoft-float -mregparm=3
CFLAGS_x86_32 += -nostdinc -include $(filter %/include/xen/config.h,$(XEN_CFLAGS))
CFLAGS_x86_32 += $(filter -I% -O%,$(XEN_CFLAGS)) -D__XEN__

# override for 32bit binaries
$(obj32): CFLAGS_stack_boundary :=
$(obj32): XEN_CFLAGS := $(CFLAGS_x86_32) -fpic

$(obj)/%.32.o: $(src)/%.c FORCE
	$(call if_changed_rule,cc_o_c)

LDFLAGS_DIRECT-$(call ld-option,--warn-rwx-segments) := --no-warn-rwx-segments
LDFLAGS_DIRECT += $(LDFLAGS_DIRECT-y)
LD32 := $(LD) $(subst x86_64,i386,$(LDFLAGS_DIRECT))

%.bin: %.lnk
	$(OBJCOPY) -j .text -O binary $< $@

%.lnk: %.32.o $(src)/build32.lds
	$(LD32) -N -T $(filter %.lds,$^) -o $@ $<

clean-files := *.lnk *.bin
