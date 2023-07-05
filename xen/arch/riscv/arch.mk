########################################
# RISCV-specific definitions

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))

CFLAGS-$(CONFIG_RISCV_64) += -mabi=lp64

riscv-march-$(CONFIG_RISCV_ISA_RV64G) := rv64g
riscv-march-$(CONFIG_RISCV_ISA_C)       := $(riscv-march-y)c

# Note that -mcmodel=medany is used so that Xen can be mapped
# into the upper half _or_ the lower half of the address space.
# -mcmodel=medlow would force Xen into the lower half.

CFLAGS += -march=$(riscv-march-y) -mstrict-align -mcmodel=medany

# TODO: Drop override when more of the build is working
override ALL_OBJS-y = arch/$(SRCARCH)/built_in.o
override ALL_LIBS-y =
