########################################
# x86-specific definitions

HAS_ACPI := y

#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#
pae ?= n
supervisor_mode_kernel ?= n

CFLAGS  += -nostdinc -fno-builtin -fno-common -fno-strict-aliasing
CFLAGS  += -iwithprefix include -Werror -Wno-pointer-arith -pipe
CFLAGS  += -I$(BASEDIR)/include 
CFLAGS  += -I$(BASEDIR)/include/asm-x86/mach-generic
CFLAGS  += -I$(BASEDIR)/include/asm-x86/mach-default

# Prevent floating-point variables from creeping into Xen.
CFLAGS  += -msoft-float

# Disable PIE/SSP if GCC supports them. They can break us.
CFLAGS  += $(call test-gcc-flag,$(CC),-nopie)
CFLAGS  += $(call test-gcc-flag,$(CC),-fno-stack-protector)
CFLAGS  += $(call test-gcc-flag,$(CC),-fno-stack-protector-all)

ifeq ($(TARGET_SUBARCH)$(pae),x86_32y)
CFLAGS  += -DCONFIG_X86_PAE=1
endif

ifeq ($(supervisor_mode_kernel),y)
CFLAGS  += -DCONFIG_X86_SUPERVISOR_MODE_KERNEL=1
endif

ifeq ($(XEN_TARGET_ARCH),x86_32)
LDFLAGS += -m elf_i386 
endif

ifeq ($(TARGET_SUBARCH),x86_64)
CFLAGS  += -mno-red-zone -fpic -fno-reorder-blocks
CFLAGS  += -fno-asynchronous-unwind-tables
LDFLAGS += -m elf_x86_64
endif

# Test for at least GCC v3.2.x.
gcc-ver = $(shell $(CC) -dumpversion | sed -e 's/^\(.\)\.\(.\)\.\(.\)/\$(1)/')
ifeq ($(call gcc-ver,1),1)
$(error gcc-1.x.x unsupported - upgrade to at least gcc-3.2.x)
endif
ifeq ($(call gcc-ver,1),2)
$(error gcc-2.x.x unsupported - upgrade to at least gcc-3.2.x)
endif
ifeq ($(call gcc-ver,1),3)
ifeq ($(call gcc-ver,2),0)
$(error gcc-3.0.x unsupported - upgrade to at least gcc-3.2.x)
endif
ifeq ($(call gcc-ver,2),1)
$(error gcc-3.1.x unsupported - upgrade to at least gcc-3.2.x)
endif
endif
