ifneq ($(KERNELRELEASE),)
obj-m += expose_p2m.o
else
PWD := $(shell pwd)
TOPDIR ?= $(abspath $(PWD)/../../../../..)
KDIR ?= $(TOPDIR)/linux-$(shell awk '/^LINUX_VER\>/{print $$3}' $(TOPDIR)/buildconfigs/mk.linux-2.6-xen)-xen
#CROSS_COMPILE ?= ia64-unknown-linux-
#ARCH ?= ia64

ifneq ($(O),)
OPT_O := O=$(realpath $(O))
endif

ifneq ($(V),)
OPT_V := V=$(V)
endif

ifneq ($(ARCH),)
OPT_ARCH := ARCH=$(ARCH)
endif

ifneq ($(CROSS_COMPILE),)
OPT_CORSS_COMPILE := CROSS_COMPILE=$(CROSS_COMPILE)
endif

default:
	$(MAKE) -C $(KDIR) $(OPT_O) $(OPT_V) $(OPT_CORSS_COMPILE) $(OPT_ARCH) M=$(PWD)
endif
