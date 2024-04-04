########################################
# RISCV-specific definitions

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))

riscv-abi-$(CONFIG_RISCV_32) := -mabi=ilp32
riscv-abi-$(CONFIG_RISCV_64) := -mabi=lp64

riscv-march-$(CONFIG_RISCV_ISA_RV64G) := rv64g
riscv-march-$(CONFIG_RISCV_ISA_C)       := $(riscv-march-y)c

riscv-generic-flags := $(riscv-abi-y) -march=$(riscv-march-y)

zbb := $(call as-insn,$(CC) $(riscv-generic-flags)_zbb,"",_zbb)
zihintpause := $(call as-insn, \
                      $(CC) $(riscv-generic-flags)_zihintpause,"pause",_zihintpause)

extensions := $(zbb) $(zihintpause)

extensions := $(subst $(space),,$(extensions))

# Note that -mcmodel=medany is used so that Xen can be mapped
# into the upper half _or_ the lower half of the address space.
# -mcmodel=medlow would force Xen into the lower half.

CFLAGS += $(riscv-generic-flags)$(extensions) -mstrict-align -mcmodel=medany

# TODO: Drop override when more of the build is working
override ALL_OBJS-y = arch/$(SRCARCH)/built_in.o
override ALL_LIBS-y =
