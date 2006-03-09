#
#  Makefile for mbootpack
#
INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk

all: build
build: mbootpack

install: build
	$(INSTALL_PROG) mbootpack $(DESTDIR)/usr/bin

#  Tools etc.
RM 	:= rm -f
GDB	:= gdb
INCS	:= -I. -I-
DEFS	:= 
LDFLAGS	:= 
CFLAGS	+= -Wpointer-arith -Wcast-qual -Wno-unused -Wno-format
CFLAGS	+= -Wmissing-prototypes -pipe

#  What object files need building for the program
OBJS	:= mbootpack.o buildimage.o

# Get gcc to generate the dependencies for us.
DEPFLAGS = -Wp,-MD,.$(@F).d
DEPS     = .*.d

mbootpack: $(OBJS)
	$(HOSTCC) -o $@ $(filter-out %.a, $^) $(LDFLAGS)

clean:
	$(RM) mbootpack *.o $(DEPS) bootsect setup bzimage_header.c bin2c

bootsect: bootsect.S
	$(CC) $(CFLAGS) $(INCS) $(DEFS) -D__MB_ASM -c bootsect.S -o bootsect.o
	$(LD) -m elf_i386 -Ttext 0x0 -s --oformat binary bootsect.o -o $@

setup: setup.S
	$(CC) $(CFLAGS) $(INCS) $(DEFS) -D__MB_ASM -c setup.S -o setup.o
	$(LD) -m elf_i386 -Ttext 0x0 -s --oformat binary setup.o -o $@

bin2c: bin2c.o 
	$(HOSTCC) -o $@ $^ 

bzimage_header.c: bootsect setup bin2c
	./bin2c -n 8 -b1 -a bzimage_bootsect bootsect > bzimage_header.c
	./bin2c -n 8 -b1 -a bzimage_setup setup >> bzimage_header.c

buildimage.c: bzimage_header.c
	@

%.o: %.S
	$(HOSTCC) $(DEPFLAGS) $(CFLAGS) $(INCS) $(DEFS) -c $< -o $@

%.o: %.c
	$(HOSTCC) $(DEPFLAGS) $(CFLAGS) $(INCS) $(DEFS) -c $< -o $@

.PHONY: all clean gdb
.PRECIOUS: $(OBJS) $(OBJS:.o=.c) $(DEPS)
.SUFFIXES: 

-include $(DEPS)

#
#  EOF
#
