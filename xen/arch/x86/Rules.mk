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

ifeq ($(TARGET_SUBARCH),x86_32)
CFLAGS  += -m32 -march=i686
LDFLAGS := --oformat elf32-i386 
endif

ifeq ($(TARGET_SUBARCH),x86_64)
CFLAGS  += -m64 -mno-red-zone -fpic -fno-reorder-blocks
CFLAGS  += -fno-asynchronous-unwind-tables
LDFLAGS := --oformat elf64-x86-64
endif
