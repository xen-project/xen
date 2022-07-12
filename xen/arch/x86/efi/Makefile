CFLAGS-y += -fshort-wchar

quiet_cmd_objcopy_o_ihex = OBJCOPY $@
cmd_objcopy_o_ihex = $(OBJCOPY) -I ihex -O binary $< $@

%.o: %.ihex FORCE
	$(call if_changed,objcopy_o_ihex)

boot.init.o: buildid.o

EFIOBJ := boot.init.o pe.init.o ebmalloc.o compat.o runtime.o

$(call cc-option-add,cflags-stack-boundary,CC,-mpreferred-stack-boundary=4)
$(EFIOBJ): CFLAGS_stack_boundary := $(cflags-stack-boundary)

obj-y := stub.o
obj-$(XEN_BUILD_EFI) := $(filter-out %.init.o,$(EFIOBJ))
obj-bin-$(XEN_BUILD_EFI) := $(filter %.init.o,$(EFIOBJ))
extra-$(XEN_BUILD_EFI) += buildid.o relocs-dummy.o
nocov-$(XEN_BUILD_EFI) += stub.o
