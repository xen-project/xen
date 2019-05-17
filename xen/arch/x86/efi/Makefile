CFLAGS += -fshort-wchar

%.o: %.ihex
	$(OBJCOPY) -I ihex -O binary $< $@

boot.init.o: buildid.o

EFIOBJ := boot.init.o compat.o runtime.o

$(EFIOBJ): CFLAGS-stack-boundary := -mpreferred-stack-boundary=4

obj-y := stub.o
obj-$(XEN_BUILD_EFI) := $(EFIOBJ) relocs-dummy.o
extra-$(XEN_BUILD_EFI) += buildid.o
nocov-$(XEN_BUILD_EFI) += stub.o
