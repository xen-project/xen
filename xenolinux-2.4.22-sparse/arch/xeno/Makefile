#
# xeno/Makefile
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

LD=$(CROSS_COMPILE)ld -m elf_i386
OBJCOPY=$(CROSS_COMPILE)objcopy -O binary -R .note -R .comment -S
LDFLAGS=-e stext
LINKFLAGS =-T $(TOPDIR)/arch/xeno/vmlinux.lds $(LDFLAGS)

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

HEAD := arch/xeno/kernel/head.o arch/xeno/kernel/init_task.o

SUBDIRS += arch/xeno/kernel arch/xeno/mm arch/xeno/lib
SUBDIRS += arch/xeno/drivers/console arch/xeno/drivers/network
SUBDIRS += arch/xeno/drivers/block arch/xeno/drivers/balloon
ifdef CONFIG_XENO_PRIV
SUBDIRS += arch/xeno/drivers/dom0 
endif

CORE_FILES += arch/xeno/kernel/kernel.o arch/xeno/mm/mm.o
CORE_FILES += arch/xeno/drivers/console/con.o
CORE_FILES += arch/xeno/drivers/block/blk.o
CORE_FILES += arch/xeno/drivers/network/net.o
ifdef CONFIG_XENO_PRIV
CORE_FILES += arch/xeno/drivers/dom0/dom0.o
endif
CORE_FILES += arch/xeno/drivers/balloon/balloon_driver.o
LIBS := $(TOPDIR)/arch/xeno/lib/lib.a $(LIBS) $(TOPDIR)/arch/xeno/lib/lib.a

arch/xeno/kernel: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xeno/kernel

arch/xeno/mm: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xeno/mm

arch/xeno/drivers/console: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xeno/drivers/console

arch/xeno/drivers/network: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xeno/drivers/network

arch/xeno/drivers/block: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xeno/drivers/block

arch/xeno/drivers/dom0: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xeno/drivers/dom0

arch/xeno/drivers/balloon: dummy
	$(MAKE) linuxsubdirs SUBDIRS=arch/xeno/drivers/balloon

MAKEBOOT = $(MAKE) -C arch/$(ARCH)/boot

vmlinux: arch/xeno/vmlinux.lds

FORCE: ;

.PHONY: bzImage compressed clean archclean archmrproper archdep

bzImage: vmlinux
	@$(MAKEBOOT) xenolinux.gz

install: bzImage
	mkdir -p /boot
	cp -a arch/$(ARCH)/boot/xenolinux.gz /boot/xenolinux.gz

dist: bzImage
	mkdir -p ../install/boot
	cp -a arch/$(ARCH)/boot/xenolinux.gz ../install/boot/xenolinux.gz

archclean:
	@$(MAKEBOOT) clean

archmrproper:

archdep:
	@$(MAKEBOOT) dep
