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

# make uname return the processor arch
UTS_MACHINE := $(XENARCH)

core-y	+= arch/xen/kernel/

include/.asm-ignore: include/asm
	@rm -f include/.asm-ignore
	@mv include/asm include/.asm-ignore
	@echo '  SYMLINK include/asm -> include/asm-$(XENARCH)'
	$(Q)if [ ! -d include ]; then mkdir -p include; fi;
	@ln -fsn asm-$(XENARCH) include/asm

include/asm-xen/asm:
	@echo '  SYMLINK $@ -> include/asm-xen/asm-$(XENARCH)'
	@ln -fsn asm-$(XENARCH) $@

arch/xen/arch:
	@rm -f $@
	@ln -fsn $(XENARCH) $@

prepare: include/.asm-ignore include/asm-xen/asm \
	arch/xen/arch ;

all: vmlinuz

vmlinuz: vmlinux
	$(Q)$(MAKE) $(build)=arch/xen/boot vmlinuz

XINSTALL_NAME ?= $(KERNELRELEASE)
install: vmlinuz
	mkdir -p $(INSTALL_PATH)/boot
	install -m0644 vmlinuz $(INSTALL_PATH)/boot/vmlinuz-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0644 vmlinux $(INSTALL_PATH)/boot/vmlinux-syms-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0664 .config $(INSTALL_PATH)/boot/config-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0664 System.map $(INSTALL_PATH)/boot/System.map-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	mkdir -p $(INSTALL_PATH)/usr/include/xen/linux
	install -m0644 include/asm-xen/linux-public/*.h $(INSTALL_PATH)/usr/include/xen/linux

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
