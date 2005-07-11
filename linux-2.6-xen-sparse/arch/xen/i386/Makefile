#
# i386/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies. Remember to do have actions
# for "archclean" cleaning up for this architecture.
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
# 20050320  Kianusch Sayah Karadji <kianusch@sk-tech.net>
#           Added support for GEODE CPU

XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

LDFLAGS		:= -m elf_i386
LDFLAGS_vmlinux :=
CHECK		:= $(CHECK) -D__i386__=1

CFLAGS += -m32
AFLAGS += -m32

CFLAGS += -pipe -msoft-float

# prevent gcc from keeping the stack 16 byte aligned
CFLAGS += $(call cc-option,-mpreferred-stack-boundary=2,)

align := $(cc-option-align)
cflags-$(CONFIG_M386)		+= -march=i386
cflags-$(CONFIG_M486)		+= -march=i486
cflags-$(CONFIG_M586)		+= -march=i586
cflags-$(CONFIG_M586TSC)	+= -march=i586
cflags-$(CONFIG_M586MMX)	+= $(call cc-option,-march=pentium-mmx,-march=i586)
cflags-$(CONFIG_M686)		+= -march=i686
cflags-$(CONFIG_MPENTIUMII)	+= -march=i686 $(call cc-option,-mtune=pentium2)
cflags-$(CONFIG_MPENTIUMIII)	+= -march=i686 $(call cc-option,-mtune=pentium3)
cflags-$(CONFIG_MPENTIUMM)	+= -march=i686 $(call cc-option,-mtune=pentium3)
cflags-$(CONFIG_MPENTIUM4)	+= -march=i686 $(call cc-option,-mtune=pentium4)
cflags-$(CONFIG_MK6)		+= -march=k6
# Please note, that patches that add -march=athlon-xp and friends are pointless.
# They make zero difference whatsosever to performance at this time.
cflags-$(CONFIG_MK7)		+= $(call cc-option,-march=athlon,-march=i686 $(align)-functions=4)
cflags-$(CONFIG_MK8)		+= $(call cc-option,-march=k8,$(call cc-option,-march=athlon,-march=i686 $(align)-functions=4))
cflags-$(CONFIG_MCRUSOE)	+= -march=i686 $(align)-functions=0 $(align)-jumps=0 $(align)-loops=0
cflags-$(CONFIG_MEFFICEON)	+= -march=i686 $(call cc-option,-mtune=pentium3) $(align)-functions=0 $(align)-jumps=0 $(align)-loops=0
cflags-$(CONFIG_MWINCHIPC6)	+= $(call cc-option,-march=winchip-c6,-march=i586)
cflags-$(CONFIG_MWINCHIP2)	+= $(call cc-option,-march=winchip2,-march=i586)
cflags-$(CONFIG_MWINCHIP3D)	+= $(call cc-option,-march=winchip2,-march=i586)
cflags-$(CONFIG_MCYRIXIII)	+= $(call cc-option,-march=c3,-march=i486) $(align)-functions=0 $(align)-jumps=0 $(align)-loops=0
cflags-$(CONFIG_MVIAC3_2)	+= $(call cc-option,-march=c3-2,-march=i686)

# AMD Elan support
cflags-$(CONFIG_X86_ELAN)	+= -march=i486

# Geode GX1 support
cflags-$(CONFIG_MGEODEGX1)		+= $(call cc-option,-march=pentium-mmx,-march=i486)

# -mregparm=3 works ok on gcc-3.0 and later
#
GCC_VERSION			:= $(shell $(CONFIG_SHELL) $(srctree)/scripts/gcc-version.sh $(CC))
cflags-$(CONFIG_REGPARM) 	+= $(shell if [ $(GCC_VERSION) -ge 0300 ] ; then echo "-mregparm=3"; fi ;)

# Disable unit-at-a-time mode, it makes gcc use a lot more stack
# due to the lack of sharing of stacklots.
CFLAGS += $(call cc-option,-fno-unit-at-a-time,)

CFLAGS += $(cflags-y)

head-y := arch/xen/i386/kernel/head.o arch/xen/i386/kernel/init_task.o

libs-y 					+= arch/i386/lib/
core-y					+= arch/xen/i386/kernel/ \
					   arch/xen/i386/mm/ \
					   arch/xen/i386/mach-default/ \
					   arch/i386/crypto/
# \
#					   arch/xen/$(mcore-y)/
drivers-$(CONFIG_MATH_EMULATION)	+= arch/i386/math-emu/
drivers-$(CONFIG_PCI)			+= arch/xen/i386/pci/
# must be linked after kernel/
drivers-$(CONFIG_OPROFILE)		+= arch/i386/oprofile/
drivers-$(CONFIG_PM)			+= arch/i386/power/

# for clean
obj-	+= kernel/ mm/ pci/
#obj-	+= ../../i386/lib/ ../../i386/mm/ 
#../../i386/$(mcore-y)/
#obj-	+= ../../i386/pci/ ../../i386/oprofile/ ../../i386/power/

xenflags-y += -Iinclude/asm-xen/asm-i386/mach-xen \
		-Iinclude/asm-i386/mach-default
CFLAGS += $(xenflags-y)
AFLAGS += $(xenflags-y)

prepare: include/asm-$(XENARCH)/asm_offsets.h
CLEAN_FILES += include/asm-$(XENARCH)/asm_offsets.h

arch/$(XENARCH)/kernel/asm-offsets.s: include/asm include/.asm-ignore \
	include/linux/version.h include/config/MARKER

include/asm-$(XENARCH)/asm_offsets.h: arch/$(XENARCH)/kernel/asm-offsets.s
	$(call filechk,gen-asm-offsets)
