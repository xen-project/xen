#
#  Makefile for mbootpack
#
INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -Wall -Werror -O3 

INCLUDES += -I $(XEN_XC)
INCLUDES += -I $(XEN_LIBXC)
CFLAGS   += $(INCLUDES)

HDRS     = $(wildcard *.h)

TARGETS  = mbootpack

INSTALL_BIN  = mbootpack
INSTALL_SBIN =

all: build
build: $(TARGETS)

install: build
	$(INSTALL_PROG) $(INSTALL_BIN) $(DESTDIR)/usr/bin

#
#  What object files need building for the program
#

OBJS	:= mbootpack.o buildimage.o
DEPS	:= mbootpack.d buildimage.d

# 
#  Tools etc.
#

RM 	:= rm -f
GDB	:= gdb
INCS	:= -I. -I-
DEFS	:= 
LDFLAGS	:= 
CC	:= gcc
CFLAGS 	:= -W -Wall -Wpointer-arith -Wcast-qual -Wno-unused -Wno-format
CFLAGS	+= -Wmissing-prototypes
#CFLAGS	+= -pipe -g -O0 -Wcast-align
CFLAGS	+= -pipe -O3 

#
#  Rules
#

mbootpack: $(OBJS)
	$(CC) -o $@ $(filter-out %.a, $^) $(LDFLAGS)

clean: FRC
	$(RM) mbootpack *.o *.d bootsect setup bzimage_header.c bin2c

bootsect: bootsect.S
	$(CC) $(CFLAGS) $(INCS) $(DEFS) -D__MB_ASM -c bootsect.S -o bootsect.o
	$(LD) -m elf_i386 -Ttext 0x0 -s --oformat binary bootsect.o -o $@

setup: setup.S
	$(CC) $(CFLAGS) $(INCS) $(DEFS) -D__MB_ASM -c setup.S -o setup.o
	$(LD) -m elf_i386 -Ttext 0x0 -s --oformat binary setup.o -o $@

bin2c: bin2c.o 
	$(CC) -o $@ $^ 

bzimage_header.c: bootsect setup bin2c
	./bin2c -n 8 -b1 -a bzimage_bootsect bootsect > bzimage_header.c
	./bin2c -n 8 -b1 -a bzimage_setup setup >> bzimage_header.c

buildimage.c buildimage.d: bzimage_header.c

%.o: %.S
	$(CC) $(CFLAGS) $(INCS) $(DEFS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INCS) $(DEFS) -c $< -o $@

%.d: %.c
	$(CC) $(CFLAGS) $(INCS) $(DEFS) -M $< > $@

FRC: 
.PHONY:: all FRC clean gdb
.PRECIOUS: $(OBJS) $(OBJS:.o=.c) $(DEPS)
.SUFFIXES: 

-include $(DEPS)

#
#  EOF
#
