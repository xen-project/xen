obj-y			:= boot.o
boot-y			:= ../../../i386/kernel/acpi/boot.o
obj-$(CONFIG_ACPI_SLEEP)	+= sleep.o wakeup.o

boot-$(CONFIG_XEN)		:= ../../../i386/kernel/acpi/boot-xen.o
