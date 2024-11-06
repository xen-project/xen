obj-bin-y += head.o
obj-bin-y += built-in-32.o
obj-bin-y += $(obj64)

obj32 := cmdline.32.o
obj32 += reloc.32.o
obj32 += reloc-trampoline.32.o

obj64 := reloc-trampoline.o

nocov-y   += $(obj32) $(obj64)
noubsan-y += $(obj32) $(obj64)
targets   += $(obj32)

obj32 := $(addprefix $(obj)/,$(obj32))

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

orphan-handling-$(call ld-option,--orphan-handling=error) := --orphan-handling=error
LDFLAGS_DIRECT-$(call ld-option,--warn-rwx-segments) := --no-warn-rwx-segments
LDFLAGS_DIRECT += $(LDFLAGS_DIRECT-y)
LD32 := $(LD) $(subst x86_64,i386,$(LDFLAGS_DIRECT))

# The parameters below tweak the generated linker scripts:
# - text_gap: padding between .text section external symbols and code.
# - text_diff: address of the .text section.
#
# Note external symbols are only affected by text_diff, while internal symbols
# are affected by both text_diff and text_gap.  Ensure the sum of gap and diff
# is greater than 2^16 so that any 16bit relocations if present in the object
# file turns into a build-time error.
text_gap := 0x010200
text_diff := 0x408020

$(obj)/build32.base.lds: AFLAGS-y += -DGAP=$(text_gap) -DTEXT_DIFF=$(text_diff)
$(obj)/build32.offset.lds: AFLAGS-y += -DGAP=$(text_gap) -DTEXT_DIFF=$(text_diff) -DAPPLY_OFFSET
$(obj)/build32.base.lds $(obj)/build32.offset.lds: $(src)/build32.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

targets += build32.offset.lds build32.base.lds

# Generate a single 32bit object.
#
# Resolve any relocations resulting from references between the translation
# units.  This ensures the same combined object file can be used to generate
# multiple images with slightly different linker scripts.
$(obj)/built-in-32.tmp.o: $(obj32)
	$(LD32) -r -o $@ $^

# Link bundle with a given layout and extract a binary from it.
# The linker will allocate GOP and resolve symbols specified in the linker
# script.
# The conversion to binary avoids polluting global symbols not used externally;
# also removes conflict with needed 64 bit GOP.
# If possible we use --orphan-handling=error option to make sure we account
# for all possible sections from C code.
$(obj)/built-in-32.%.bin: $(obj)/build32.%.lds $(obj)/built-in-32.tmp.o
	$(LD32) $(orphan-handling-y) -N -T $< -o $(@:bin=o) $(filter %.o,$^)
	$(NM) -p --format=bsd $(@:bin=o) > $(@:bin=map)
	$(OBJCOPY) -j .text -O binary $(@:bin=o) $@
	rm -f $(@:bin=o)

quiet_cmd_combine = GEN     $@
cmd_combine = \
    $(PYTHON) $(srctree)/tools/combine_two_binaries.py \
              --gap       $(text_gap) \
              --text-diff $(text_diff) \
              --script    $(obj)/build32.base.lds \
              --bin1      $(obj)/built-in-32.base.bin \
              --bin2      $(obj)/built-in-32.offset.bin \
              --map       $(obj)/built-in-32.base.map \
              --exports   cmdline_parse_early,reloc,reloc_trampoline32 \
              --output    $@

targets += built-in-32.S

# generate final object file combining and checking above binaries
$(obj)/built-in-32.S: $(obj)/built-in-32.base.bin $(obj)/built-in-32.offset.bin \
                      $(srctree)/tools/combine_two_binaries.py FORCE
	$(call if_changed,combine)

clean-files := built-in-32.*.bin built-in-32.*.map build32.*.lds
