obj-$(CONFIG_ACPI_BOOT)		:= boot.o
obj-$(CONFIG_X86_IO_APIC)	+= earlyquirk.o
obj-$(CONFIG_ACPI_SLEEP)	+= sleep.o wakeup.o

ifdef CONFIG_XEN
include $(srctree)/scripts/Makefile.xen
obj-y := $(call cherrypickxen, $(obj-y), $(src))
endif
