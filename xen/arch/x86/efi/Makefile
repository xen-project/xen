CFLAGS += -fshort-wchar

obj-y += stub.o

create = test -e $(1) || touch -t 199901010000 $(1)

efi := $(filter y,$(x86_64)$(shell rm -f disabled))
efi := $(if $(efi),$(shell $(CC) $(filter-out $(CFLAGS-y) .%.d,$(CFLAGS)) -c check.c 2>disabled && echo y))
efi := $(if $(efi),$(shell $(LD) -mi386pep --subsystem=10 -o check.efi check.o 2>disabled && echo y))
efi := $(if $(efi),$(shell rm disabled)y,$(shell $(call create,boot.init.o); $(call create,runtime.o)))

extra-$(efi) += boot.init.o relocs-dummy.o runtime.o compat.o

stub.o: $(extra-y)
