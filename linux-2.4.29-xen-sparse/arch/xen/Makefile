#
# xen/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies. Remember to do have actions
# for "archclean" and "archdep" for cleaning up and making dependencies for
# this architecture
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 1994 by Linus Torvalds
#
# 19990713  Artur Skawina <skawina@geocities.com>
#           Added '-march' and '-mpreferred-stack-boundary' support
#

# If no .config file exists then use the appropriate defconfig-* file
ifneq (.config,$(wildcard .config))
DUMMYX:=$(shell cp $(TOPDIR)/arch/xen/defconfig$(EXTRAVERSION) $(TOPDIR)/.config)
-include $(TOPDIR)/.config
endif

LD=$(CROSS_COMPILE)ld -m elf_i386
OBJCOPY=$(CROSS_COMPILE)objcopy -R .note -R .comment -S
LDFLAGS=-e stext
LINKFLAGS =-T $(TOPDIR)/arch/xen/vmlinux.lds $(LDFLAGS)

CFLAGS += -pipe

check_gcc = $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi)

# prevent gcc from keeping the stack 16 byte aligned
CFLAGS += $(call check_gcc,-mpreferred-stack-boundary=2,)

ifdef CONFIG_M686
CFLAGS += -march=i686
endif

ifdef CONFIG_MPENTIUMIII
CFLAGS += -march=i686
endif

ifdef CONFIG_MPENTIUM4
CFLAGS += -march=i686
endif

ifdef CONFIG_MK7
CFLAGS += $(call check_gcc,-march=athlon,-march=i686 -malign-functions=4)
endif

# Disable unit-at-a-time mode, it makes gcc use a lot more stack
# due to the lack of sharing of stacklots.
CFLAGS += $(call check_gcc,-fno-unit-at-a-time,)

HEAD := arch/xen/kernel/head.o arch/xen/kernel/init_task.o

SUBDIRS += arch/xen/kernel arch/xen/mm arch/xen/lib
SUBDIRS += arch/xen/drivers/console 
SUBDIRS += arch/xen/drivers/evtchn
SUBDIRS += arch/xen/drivers/blkif
SUBDIRS += arch/xen/drivers/netif
SUBDIRS += arch/xen/drivers/balloon
ifdef CONFIG_XEN_PRIVILEGED_GUEST
SUBDIRS += arch/xen/drivers/dom0 
endif

CORE_FILES += arch/xen/kernel/kernel.o arch/xen/mm/mm.o
CORE_FILES += arch/xen/drivers/evtchn/drv.o
CORE_FILES += arch/xen/drivers/console/drv.o
DRIVERS += arch/xen/drivers/blkif/drv.o
DRIVERS += arch/xen/drivers/netif/drv.o
ifdef CONFIG_XEN_PRIVILEGED_GUEST
CORE_FILES += arch/xen/drivers/dom0/drv.o
endif
CORE_FILES += arch/xen/drivers/balloon/drv.o
LIBS := $(TOPDIR)/arch/xen/lib/lib.a $(LIBS) $(TOPDIR)/arch/xen/lib/lib.a

arch/xen/kernel: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xen/kernel

arch/xen/mm: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xen/mm

arch/xen/drivers/console: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xen/drivers/console

arch/xen/drivers/network: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xen/drivers/network

arch/xen/drivers/block: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xen/drivers/block

arch/xen/drivers/dom0: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xen/drivers/dom0

arch/xen/drivers/balloon: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xen/drivers/balloon

MAKEBOOT = $(MAKE) -C arch/$(ARCH)/boot

vmlinux: arch/xen/vmlinux.lds

FORCE: ;

.PHONY: bzImage compressed clean archclean archmrproper archdep


bzImage: vmlinux
	@$(MAKEBOOT) bzImage

INSTALL_NAME ?= $(KERNELRELEASE)
install: bzImage
	mkdir -p $(INSTALL_PATH)/boot
	ln -f -s vmlinuz-$(INSTALL_NAME)$(INSTALL_SUFFIX) $(INSTALL_PATH)/boot/vmlinuz-$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(XENGUEST)$(INSTALL_SUFFIX)
	rm -f $(INSTALL_PATH)/boot/vmlinuz-$(INSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0644 arch/$(ARCH)/boot/bzImage $(INSTALL_PATH)/boot/vmlinuz-$(INSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0644 vmlinux $(INSTALL_PATH)/boot/vmlinux-syms-$(INSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0664 .config $(INSTALL_PATH)/boot/config-$(INSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0664 System.map $(INSTALL_PATH)/boot/System.map-$(INSTALL_NAME)$(INSTALL_SUFFIX)
	ln -f -s vmlinuz-$(INSTALL_NAME)$(INSTALL_SUFFIX) $(INSTALL_PATH)/boot/vmlinuz-$(VERSION).$(PATCHLEVEL)$(XENGUEST)$(INSTALL_SUFFIX)

%_config: arch/xen/defconfig-%
	rm -f .config arch/xen/defconfig
	cp -f arch/xen/defconfig-$(@:_config=) arch/xen/defconfig
	cp -f arch/xen/defconfig-$(@:_config=) .config


archclean:
	@$(MAKEBOOT) clean

archmrproper:
	rm -f include/asm-xen/xen-public/arch

archdep:
	@$(MAKEBOOT) dep
