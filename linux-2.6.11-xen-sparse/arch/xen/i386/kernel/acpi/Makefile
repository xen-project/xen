obj-$(CONFIG_ACPI_BOOT)		        := boot.o
c-obj-$(CONFIG_X86_IO_APIC)	        += earlyquirk.o
c-obj-$(CONFIG_ACPI_SLEEP)	        += sleep.o wakeup.o

c-link                                  :=

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-link)):
	@ln -fsn $(srctree)/arch/i386/kernel/acpi/$(notdir $@) $@

