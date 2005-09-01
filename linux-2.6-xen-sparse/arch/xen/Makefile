#
# xen/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies. Remember to do have actions
# for "archclean" cleaning up for this architecture.
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 2004 by Christian Limpach
#

XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

# pick up headers from include/asm-xen/asm in preference over include/asm
NOSTDINC_FLAGS  = -nostdinc -iwithprefix include/asm-xen -Iinclude/asm-xen -iwithprefix include
ifneq ($(KBUILD_SRC),)
NOSTDINC_FLAGS += -I$(srctree)/include/asm-xen
endif

# make uname return the processor arch
UTS_MACHINE := $(XENARCH)

core-y	+= arch/xen/kernel/

.PHONY: include2/asm
include2/asm:
ifneq ($(KBUILD_SRC),)
	@echo '  SYMLINK ../include/asm-$(XENARCH) -> include2/asm'
	$(Q)ln -fsn ../include/asm-$(XENARCH) include2/asm
endif

include/.asm-ignore: include/asm
	@rm -f include/.asm-ignore
	@mv include/asm include/.asm-ignore
	@echo '  SYMLINK include/asm -> include/asm-$(XENARCH)'
	$(Q)if [ ! -d include ]; then mkdir -p include; fi;
	@ln -fsn $(srctree)/include/asm-$(XENARCH) include/asm

include/asm-xen/asm:
	@echo '  SYMLINK $@ -> include/asm-xen/asm-$(XENARCH)'
	@mkdir -p include/asm-xen
	@ln -fsn $(srctree)/include/asm-xen/asm-$(XENARCH) $@

arch/xen/arch:
	@rm -f $@
	@mkdir -p arch/xen
	@ln -fsn $(srctree)/arch/xen/$(XENARCH) $@

arch/$(XENARCH)/kernel/asm-offsets.s: include/asm include/linux/version.h \
				   include/config/MARKER

include/asm-$(ARCH)/asm_offsets.h: arch/$(XENARCH)/kernel/asm-offsets.s
	$(call filechk,gen-asm-offsets)

prepare: include/.asm-ignore include/asm-xen/asm \
	arch/xen/arch include/asm-$(ARCH)/asm_offsets.h include2/asm ;

all: vmlinuz

vmlinuz: vmlinux
	$(Q)$(MAKE) $(build)=arch/xen/boot vmlinuz

XINSTALL_NAME ?= $(KERNELRELEASE)
install: vmlinuz
install kernel_install:
	mkdir -p $(INSTALL_PATH)/boot
	ln -f -s vmlinuz-$(XINSTALL_NAME)$(INSTALL_SUFFIX) $(INSTALL_PATH)/boot/vmlinuz-$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(XENGUEST)$(INSTALL_SUFFIX)
	rm -f $(INSTALL_PATH)/boot/vmlinuz-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0644 vmlinuz $(INSTALL_PATH)/boot/vmlinuz-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0644 vmlinux $(INSTALL_PATH)/boot/vmlinux-syms-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0664 .config $(INSTALL_PATH)/boot/config-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0664 System.map $(INSTALL_PATH)/boot/System.map-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	ln -f -s vmlinuz-$(XINSTALL_NAME)$(INSTALL_SUFFIX) $(INSTALL_PATH)/boot/vmlinuz-$(VERSION).$(PATCHLEVEL)$(XENGUEST)$(INSTALL_SUFFIX)
	mkdir -p $(INSTALL_PATH)/usr/include/xen/linux
	install -m0644 $(srctree)/include/asm-xen/linux-public/*.h $(INSTALL_PATH)/usr/include/xen/linux

archclean:
	@if [ -e arch/xen/arch ]; then $(MAKE) $(clean)=arch/xen/arch; fi;
	@rm -f arch/xen/arch include/.asm-ignore include/asm-xen/asm
	@rm -f vmlinux-stripped vmlinuz

define archhelp
  echo  '* vmlinuz	- Compressed kernel image'
  echo  '  install	- Install kernel image and config file'
endef

ifneq ($(XENARCH),)
include	$(srctree)/arch/xen/$(XENARCH)/Makefile
endif
