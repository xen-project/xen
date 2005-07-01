i386-obj-$(CONFIG_ACPI_BOOT)		:= boot.o
c-obj-$(CONFIG_X86_IO_APIC)	        := earlyquirk.o
c-obj-$(CONFIG_ACPI_SLEEP)	        += sleep.o
s-obj-$(CONFIG_ACPI_SLEEP)	        += wakeup.o

c-link                                  :=

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-link)):
	@ln -fsn $(srctree)/arch/i386/kernel/acpi/$(notdir $@) $@

$(patsubst %.o,$(obj)/%.S,$(s-obj-y) $(s-link)):
	@ln -fsn $(srctree)/arch/x86_64/kernel/acpi/$(notdir $@) $@

$(patsubst %.o,$(obj)/%.c,$(i386-obj-y)):
	@ln -fsn $(srctree)/arch/xen/i386/kernel/acpi/$(notdir $@) $@

obj-y	+= $(c-obj-y) $(s-obj-y) $(i386-obj-y)

clean-files += $(patsubst %.o,%.c,$(c-obj-y) $(c-obj-) $(c-link))
clean-files += $(patsubst %.o,%.S,$(s-obj-y) $(s-obj-) $(s-link))
