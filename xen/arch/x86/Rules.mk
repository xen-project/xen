########################################
# x86-specific definitions

CC := gcc
LD := ld

CFLAGS  := -nostdinc -fno-builtin -fno-common -fno-strict-aliasing -O3
CFLAGS  += -iwithprefix include -Wall -Werror -fomit-frame-pointer
CFLAGS  += -I$(BASEDIR)/include -Wno-pointer-arith -Wredundant-decls

LDFLAGS := -T xen.lds -N 

ifeq ($(TARGET_SUBARCH),x86_32)
CFLAGS += -m32 -march=i686
LDARCHFLAGS := --oformat elf32-i386 
endif

ifeq ($(TARGET_SUBARCH),x86_64)
CFLAGS += -m64
LDARCHFLAGS := --oformat elf64-x86-64
endif
