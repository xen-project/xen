XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk

# Should make makefiles export linux build directory!
# This is a fragile hack to tide us over
ifeq ($(KERNELS),linux-2.6-xen)
LINUX_VER=2.6.18-xen
endif
ifeq ($(KERNELS),linux-2.6-xen0)
LINUX_VER=2.6.18-xen0
endif

KERNELDIR ?= $(XEN_ROOT)/build-linux-$(LINUX_VER)_$(XEN_TARGET_ARCH)

.PHONY: all
all:
	if test -d $(KERNELDIR); then $(MAKE) -C $(KERNELDIR) SUBDIRS=`pwd` modules; fi

.PHONY: install
install: all
	if test -d $(KERNELDIR); then $(MAKE) -C $(KERNELDIR) SUBDIRS=`pwd` INSTALL_MOD_PATH=$(DESTDIR) modules_install; fi

clean::
	-rm -rf *.o *.ko *.mod.c *.mod.o Module.symvers .*.cmd .tmp_versions
