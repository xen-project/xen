obj-$(CONFIG_XEN_PCIDEV_BACKEND) += pciback.o

pciback-y := pci_stub.o pciback_ops.o xenbus.o
pciback-y += conf_space.o conf_space_header.o
pciback-$(CONFIG_XEN_PCIDEV_BACKEND_VPCI) += vpci.o
pciback-$(CONFIG_XEN_PCIDEV_BACKEND_PASS) += passthrough.o

ifeq ($(CONFIG_XEN_PCIDEV_BE_DEBUG),y)
EXTRA_CFLAGS += -DDEBUG
endif
