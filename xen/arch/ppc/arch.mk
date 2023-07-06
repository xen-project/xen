########################################
# Power-specific definitions

ppc-march-$(CONFIG_POWER_ISA_2_07B) := power8
ppc-march-$(CONFIG_POWER_ISA_3_00) := power9

CFLAGS += -m64 -mlittle-endian -mcpu=$(ppc-march-y)
CFLAGS += -mstrict-align -mcmodel=large -mabi=elfv2 -mno-altivec -mno-vsx

LDFLAGS += -m elf64lppc

# TODO: Drop override when more of the build is working
override ALL_OBJS-y = arch/$(SRCARCH)/built_in.o
override ALL_LIBS-y =
