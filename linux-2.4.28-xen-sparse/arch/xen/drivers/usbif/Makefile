
O_TARGET := drv.o

subdir-$(CONFIG_XEN_USB_FRONTEND) += frontend
obj-$(CONFIG_XEN_USB_FRONTEND) += frontend/drv.o

subdir-$(CONFIG_XEN_USB_BACKEND) += backend
obj-$(CONFIG_XEN_USB_BACKEND)    += backend/drv.o

include $(TOPDIR)/Rules.make
