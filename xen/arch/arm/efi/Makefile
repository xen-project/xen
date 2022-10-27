include $(srctree)/common/efi/efi-common.mk

ifeq ($(CONFIG_ARM_EFI),y)
obj-y += $(EFIOBJ-y)
obj-$(CONFIG_ACPI) +=  efi-dom0.init.o
else
obj-y += common-stub.o

$(obj)/common-stub.o: CFLAGS-y += -fno-short-wchar

endif
