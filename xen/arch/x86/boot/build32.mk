override XEN_TARGET_ARCH=x86_32
CFLAGS =
include $(XEN_ROOT)/Config.mk

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))

CFLAGS += -Werror -fno-builtin -msoft-float
CFLAGS := $(filter-out -flto,$(CFLAGS)) 

# NB. awk invocation is a portable alternative to 'head -n -1'
%.S: %.bin
	(od -v -t x $< | tr -s ' ' | awk 'NR > 1 {print s} {s=$$0}' | \
	sed 's/ /,0x/g' | sed 's/,0x$$//' | sed 's/^[0-9]*,/ .long /') >$@

%.bin: %.lnk
	$(OBJCOPY) -O binary $< $@

%.lnk: %.o
	$(LD) $(LDFLAGS_DIRECT) -N -Ttext 0 -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -fpic $< -o $@
	$(OBJDUMP) -h $@ | sed -n '/[0-9]/{s,00*,0,g;p;}' |\
		while read idx name sz rest; do \
			case "$$name" in \
			.data|.data.*|.rodata|.rodata.*|.bss|.bss.*) \
				test $$sz != 0 || continue; \
				echo "Error: non-empty $$name: 0x$$sz" >&2; \
				exit $$(expr $$idx + 1);; \
			esac; \
		done

reloc.o: reloc.c $(RELOC_DEPS)

.PRECIOUS: %.bin %.lnk
