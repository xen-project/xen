obj-y	+= xenbus.o

xenbus-objs =
xenbus-objs += xenbus_comms.o
xenbus-objs += xenbus_xs.o
xenbus-objs += xenbus_probe.o 

XEN_TOOLS_DIR := "../tools"
vpath %.h $(XEN_TOOLS_DIR)
EXTRA_CFLAGS += -I $(XEN_TOOLS_DIR)
