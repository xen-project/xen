CFLAGS-y += -fshort-wchar

quiet_cmd_objcopy_o_ihex = OBJCOPY $@
cmd_objcopy_o_ihex = $(OBJCOPY) -I ihex -O binary $< $@

$(obj)/%.o: $(src)/%.ihex FORCE
	$(call if_changed,objcopy_o_ihex)

$(obj)/boot.init.o: $(obj)/buildid.o

EFIOBJ-y := boot.init.o pe.init.o ebmalloc.o runtime.o
EFIOBJ-$(CONFIG_COMPAT) += compat.o

$(call cc-option-add,cflags-stack-boundary,CC,-mpreferred-stack-boundary=4)
$(addprefix $(obj)/,$(EFIOBJ-y)): CFLAGS_stack_boundary := $(cflags-stack-boundary)

obj-y := stub.o
obj-$(XEN_BUILD_EFI) := $(filter-out %.init.o,$(EFIOBJ-y))
obj-bin-$(XEN_BUILD_EFI) := $(filter %.init.o,$(EFIOBJ-y))
extra-$(XEN_BUILD_EFI) += buildid.o relocs-dummy.o
nocov-$(XEN_BUILD_EFI) += stub.o
