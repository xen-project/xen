CFLAGS += -fshort-wchar

efi := y$(shell rm -f disabled)
efi := $(if $(efi),$(shell $(CC) $(filter-out $(CFLAGS-y) .%.d,$(CFLAGS)) -c check.c 2>disabled && echo y))
efi := $(if $(efi),$(shell $(LD) -mi386pep --subsystem=10 -o check.efi check.o 2>disabled && echo y))
efi := $(if $(efi),$(shell rm disabled)y)

%.o: %.ihex
	$(OBJCOPY) -I ihex -O binary $< $@

boot.init.o: buildid.o

obj-y := stub.o
obj-$(efi) := boot.init.o compat.o relocs-dummy.o runtime.o
extra-$(efi) += buildid.o
nocov-$(efi) += stub.o
