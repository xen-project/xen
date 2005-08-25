#
# x86_64/Makefile
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
# 20000913  Pavel Machek <pavel@suse.cz>
#	    Converted for x86_64 architecture
# 20010105  Andi Kleen, add IA32 compiler.
#           ....and later removed it again....
# 20050205  Jun Nakajima <jun.nakajima@intel.com> 
#           Modified for Xen
#
# $Id: Makefile,v 1.31 2002/03/22 15:56:07 ak Exp $

#
# early bootup linking needs 32bit. You can either use real 32bit tools
# here or 64bit tools in 32bit mode.
#
XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

IA32_CC := $(CC) $(CPPFLAGS) -m32 -O2 -fomit-frame-pointer
IA32_LD := $(LD) -m elf_i386
IA32_AS := $(CC) $(AFLAGS) -m32 -Wa,--32 -traditional -c
IA32_OBJCOPY := $(CROSS_COMPILE)objcopy
IA32_CPP := $(CROSS_COMPILE)gcc -m32 -E
export IA32_CC IA32_LD IA32_AS IA32_OBJCOPY IA32_CPP


LDFLAGS		:= -m elf_x86_64
#LDFLAGS_vmlinux := -e stext

CHECKFLAGS      += -D__x86_64__ -m64

cflags-$(CONFIG_MK8) += $(call cc-option,-march=k8)
cflags-$(CONFIG_MPSC) += $(call cc-option,-march=nocona)
CFLAGS += $(cflags-y)

CFLAGS += -mno-red-zone
CFLAGS += -mcmodel=kernel
CFLAGS += -pipe
# this makes reading assembly source easier, but produces worse code
# actually it makes the kernel smaller too.
CFLAGS += -fno-reorder-blocks	
CFLAGS += -Wno-sign-compare
ifneq ($(CONFIG_DEBUG_INFO),y)
CFLAGS += -fno-asynchronous-unwind-tables
# -fweb shrinks the kernel a bit, but the difference is very small
# it also messes up debugging, so don't use it for now.
#CFLAGS += $(call cc-option,-fweb)
endif
# -funit-at-a-time shrinks the kernel .text considerably
# unfortunately it makes reading oopses harder.
CFLAGS += $(call cc-option,-funit-at-a-time,)

head-y := arch/xen/x86_64/kernel/head.o arch/xen/x86_64/kernel/head64.o arch/xen/x86_64/kernel/init_task.o

libs-y 					+= arch/x86_64/lib/
core-y					+= arch/xen/x86_64/kernel/ arch/xen/x86_64/mm/
core-$(CONFIG_IA32_EMULATION)		+= arch/xen/x86_64/ia32/
drivers-$(CONFIG_PCI)			+= arch/xen/x86_64/pci/
drivers-$(CONFIG_OPROFILE)		+= arch/x86_64/oprofile/

# for clean
obj-	+= kernel/ mm/ pci/

xenflags-y += -Iinclude/asm-xen/asm-x86_64/mach-xen

CFLAGS += $(xenflags-y)
AFLAGS += $(xenflags-y)

prepare: include/asm-$(XENARCH)/asm_offsets.h
CLEAN_FILES += include/asm-$(XENARCH)/asm_offsets.h

arch/$(XENARCH)/kernel/asm-offsets.s: include/asm include/.asm-ignore \
	include/linux/version.h include/config/MARKER

include/asm-$(XENARCH)/offset.h: arch/$(XENARCH)/kernel/asm-offsets.s
	$(call filechk,gen-asm-offsets)

include/asm-$(XENARCH)/asm_offsets.h: include/asm-$(XENARCH)/offset.h
	ln -fsn offset.h include/asm-$(XENARCH)/asm_offsets.h
	ln -fsn offset.h include/asm-$(XENARCH)/asm_offset.h
