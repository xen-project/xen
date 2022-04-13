obj-bin-y += head.o
head-srcs := cmdline.S reloc.S

nocov-y += $(head-srcs:.S=.o)
noubsan-y += $(head-srcs:.S=.o)
targets += $(head-srcs:.S=.o)

head-srcs := $(addprefix $(obj)/, $(head-srcs))

ifdef building_out_of_srctree
$(obj)/head.o: CFLAGS-y += -iquote $(obj)
endif
$(obj)/head.o: $(head-srcs)

CFLAGS_x86_32 := $(subst -m64,-m32 -march=i686,$(XEN_TREEWIDE_CFLAGS))
$(call cc-options-add,CFLAGS_x86_32,CC,$(EMBEDDED_EXTRA_CFLAGS))
CFLAGS_x86_32 += -Werror -fno-builtin -g0 -msoft-float
ifdef building_out_of_srctree
CFLAGS_x86_32 += -I$(objtree)/include
endif
CFLAGS_x86_32 += -I$(srctree)/include

# override for 32bit binaries
$(head-srcs:.S=.o): CFLAGS_stack_boundary :=
$(head-srcs:.S=.o): XEN_CFLAGS := $(CFLAGS_x86_32) -fpic

$(head-srcs): %.S: %.bin
	(od -v -t x $< | tr -s ' ' | awk 'NR > 1 {print s} {s=$$0}' | \
	sed 's/ /,0x/g' | sed 's/,0x$$//' | sed 's/^[0-9]*,/ .long /') >$@

# Drop .got.plt during conversion to plain binary format.
# Please check build32.lds for more details.
%.bin: %.lnk
	$(OBJDUMP) -h $< | sed -n '/[0-9]/{s,00*,0,g;p;}' | \
		while read idx name sz rest; do \
			case "$$name" in \
			.got.plt) \
				test $$sz != 0c || continue; \
				echo "Error: non-empty $$name: 0x$$sz" >&2; \
				exit $$(expr $$idx + 1);; \
			esac; \
		done
	$(OBJCOPY) -O binary -R .got.plt $< $@

%.lnk: %.o $(src)/build32.lds
	$(LD) $(subst x86_64,i386,$(LDFLAGS_DIRECT)) -N -T $(filter %.lds,$^) -o $@ $<

clean-files := cmdline.S reloc.S *.lnk *.bin
