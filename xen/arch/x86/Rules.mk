########################################
# x86-specific definitions

CC := gcc
LD := ld

CFLAGS  := -nostdinc -fno-builtin -fno-common -fno-strict-aliasing
CFLAGS  += -iwithprefix include -Wall -Werror -pipe
CFLAGS  += -I$(BASEDIR)/include -Wno-pointer-arith -Wredundant-decls

ifeq ($(optimize),y)
CFLAGS  += -O3 -fomit-frame-pointer
else
x86_32/usercopy.o: CFLAGS += -O1
endif

# Prevent floating-point variables from creeping into Xen.
CFLAGS  += -msoft-float

# Disable PIE/SSP if GCC supports them. They can break us.
CFLAGS  += $(call test-gcc-flag,-nopie)
CFLAGS  += $(call test-gcc-flag,-fno-stack-protector)
CFLAGS  += $(call test-gcc-flag,-fno-stack-protector-all)

ifeq ($(TARGET_SUBARCH),x86_32)
CFLAGS  += -m32 -march=i686
LDFLAGS := --oformat elf32-i386 
endif

ifeq ($(TARGET_SUBARCH),x86_64)
CFLAGS  += -m64 -mno-red-zone -fpic -fno-reorder-blocks
CFLAGS  += -fno-asynchronous-unwind-tables
LDFLAGS := --oformat elf64-x86-64
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
