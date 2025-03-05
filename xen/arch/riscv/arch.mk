########################################
# RISCV-specific definitions

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))

riscv-abi-$(CONFIG_RISCV_32) := -mabi=ilp32
riscv-abi-$(CONFIG_RISCV_64) := -mabi=lp64

riscv-march-$(CONFIG_RISCV_ISA_RV64G) := rv64g
riscv-march-$(CONFIG_RISCV_ISA_C)       := $(riscv-march-y)c

riscv-generic-flags := $(riscv-abi-y) -march=$(riscv-march-y)

# check-extension: Check whether extenstion is supported by a compiler and
#                  an assembler.
# Usage: $(call check-extension,extension_name).
#        it should be defined variable with following name:
#          <extension name>-insn := "insn"
#        which represents an instruction of extension support of which is
#        going to be checked.
define check-extension =
$(eval $(1) := \
	$(call as-insn,$(CC) $(riscv-generic-flags)_$(1),$(value $(1)-insn),_$(1)))
endef

zbb-insn := "andn t0$(comma)t0$(comma)t0"
$(call check-extension,zbb)

zihintpause-insn := "pause"
$(call check-extension,zihintpause)

extensions := $(zbb) $(zihintpause)

extensions := $(subst $(space),,$(extensions))

# Note that -mcmodel=medany is used so that Xen can be mapped
# into the upper half _or_ the lower half of the address space.
# -mcmodel=medlow would force Xen into the lower half.

CFLAGS += $(riscv-generic-flags)$(extensions) -mstrict-align -mcmodel=medany
