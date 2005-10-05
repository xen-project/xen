#
# Makefile for the kernel tpm device drivers.
#
ifeq ($(CONFIG_XEN_PHYSDEV_ACCESS),y)
obj-$(CONFIG_TCG_TPM) += tpm.o
obj-$(CONFIG_TCG_NSC) += tpm_nsc.o
obj-$(CONFIG_TCG_ATMEL) += tpm_atmel.o
obj-$(CONFIG_TCG_TIS) += tpm_tis.o
obj-$(CONFIG_TCG_XEN) += tpm_xen.o
else
obj-$(CONFIG_TCG_TPM) += tpm.o
obj-$(CONFIG_TCG_XEN) += tpm_xen.o
endif
