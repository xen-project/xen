obj-y += xenbus_client.o xenbus_comms.o xenbus_xs.o xenbus_probe.o
obj-$(CONFIG_XEN_BACKEND) += xenbus_be.o

xenbus_be-objs =
xenbus_be-objs += xenbus_backend_client.o

xenbus-$(CONFIG_XEN_BACKEND) += xenbus_probe_backend.o
obj-y += $(xenbus-y) $(xenbus-m)
obj-$(CONFIG_XEN_XENBUS_DEV) += xenbus_dev.o
