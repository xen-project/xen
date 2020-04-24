CFLAGS-y += -fshort-wchar

%.o: %.ihex
	$(OBJCOPY) -I ihex -O binary $< $@

boot.init.o: buildid.o

EFIOBJ := boot.init.o compat.o runtime.o

$(call cc-option-add,cflags-stack-boundary,CC,-mpreferred-stack-boundary=4)
$(EFIOBJ): CFLAGS-stack-boundary := $(cflags-stack-boundary)

obj-y := stub.o
obj-$(XEN_BUILD_EFI) := $(EFIOBJ) relocs-dummy.o
extra-$(XEN_BUILD_EFI) += buildid.o
nocov-$(XEN_BUILD_EFI) += stub.o
