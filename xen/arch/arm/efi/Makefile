include $(srctree)/common/efi/efi-common.mk

ifeq ($(CONFIG_ARM_EFI),y)
obj-y += $(EFIOBJ-y)
obj-$(CONFIG_ACPI) +=  efi-dom0.init.o
else
# Add stub.o to EFIOBJ-y to re-use the clean-files in
# efi-common.mk. Otherwise the link of stub.c in arm/efi
# will not be cleaned in "make clean".
EFIOBJ-y += stub.o
obj-y += stub.o
endif
