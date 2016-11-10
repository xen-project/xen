CFLAGS += -fshort-wchar

obj-y += stub.o

create = test -e $(1) || touch -t 199901010000 $(1)

efi := y$(shell rm -f disabled)
efi := $(if $(efi),$(shell $(CC) $(filter-out $(CFLAGS-y) .%.d,$(CFLAGS)) -c check.c 2>disabled && echo y))
efi := $(if $(efi),$(shell $(LD) -mi386pep --subsystem=10 -o check.efi check.o 2>disabled && echo y))
efi := $(if $(efi),$(shell rm disabled)y,$(shell $(call create,boot.init.o); $(call create,runtime.o)))

extra-$(efi) += boot.init.o relocs-dummy.o runtime.o compat.o buildid.o

%.o: %.ihex
	$(OBJCOPY) -I ihex -O binary $< $@

cc-runtime.o := $(CC) -mno-sse
$(call cc-option-add,cflags-runtime.o,cc-runtime.o,-mpreferred-stack-boundary=3)
$(call cc-option-add,cflags-runtime.o,cc-runtime.o,-mincoming-stack-boundary=3)
runtime.o: CFLAGS += $(cflags-runtime.o)

stub.o: $(extra-y)
nogcov-$(efi) += stub.o
