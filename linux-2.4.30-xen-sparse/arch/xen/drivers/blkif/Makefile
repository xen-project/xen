
O_TARGET := drv.o

subdir-$(CONFIG_XEN_BLKDEV_FRONTEND) += frontend
obj-$(CONFIG_XEN_BLKDEV_FRONTEND)    += frontend/drv.o

subdir-$(CONFIG_XEN_PHYSDEV_ACCESS) += backend
obj-$(CONFIG_XEN_PHYSDEV_ACCESS)    += backend/drv.o

include $(TOPDIR)/Rules.make
