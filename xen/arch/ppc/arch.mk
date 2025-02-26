########################################
# Power-specific definitions

ppc-march-$(CONFIG_POWER_ISA_3_00) := power9

CFLAGS += -m64 -mlittle-endian -mcpu=$(ppc-march-y)
CFLAGS += -mstrict-align -mcmodel=medium -mabi=elfv2 -fPIC -mno-altivec -mno-vsx -msoft-float

LDFLAGS += -m elf64lppc

ifeq ($(CONFIG_UBSAN),y)
# Don't enable alignment sanitisation since Power ISA guarantees hardware
# support for unaligned accesses.
$(call cc-option-add,CFLAGS_UBSAN,CC,-fno-sanitize=alignment)
endif
