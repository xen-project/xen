obj-bin-y += head.o

head-bin-objs := cmdline.o reloc.o

nocov-y   += $(head-bin-objs)
noubsan-y += $(head-bin-objs)
targets   += $(head-bin-objs)

head-bin-objs := $(addprefix $(obj)/,$(head-bin-objs))

$(obj)/head.o: AFLAGS-y += -Wa$(comma)-I$(obj)
$(obj)/head.o: $(head-bin-objs:.o=.bin)

CFLAGS_x86_32 := $(subst -m64,-m32 -march=i686,$(XEN_TREEWIDE_CFLAGS))
$(call cc-options-add,CFLAGS_x86_32,CC,$(EMBEDDED_EXTRA_CFLAGS))
CFLAGS_x86_32 += -Werror -fno-builtin -g0 -msoft-float
ifdef building_out_of_srctree
CFLAGS_x86_32 += -I$(objtree)/include
endif
CFLAGS_x86_32 += -I$(srctree)/include

# override for 32bit binaries
$(head-bin-objs): CFLAGS_stack_boundary :=
$(head-bin-objs): XEN_CFLAGS := $(CFLAGS_x86_32) -fpic

LDFLAGS_DIRECT-$(call ld-option,--warn-rwx-segments) := --no-warn-rwx-segments
LDFLAGS_DIRECT += $(LDFLAGS_DIRECT-y)

%.bin: %.lnk
	$(OBJCOPY) -j .text -O binary $< $@

%.lnk: %.o $(src)/build32.lds
	$(LD) $(subst x86_64,i386,$(LDFLAGS_DIRECT)) -N -T $(filter %.lds,$^) -o $@ $<

clean-files := *.lnk *.bin
