#
#  Makefile for mbootpack
#
XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: build

.PHONY: build
build: mbootpack

.PHONY: install
install: build
	$(INSTALL_PROG) mbootpack $(DESTDIR)/usr/bin

#  Tools etc.
RM 	:= rm -f
INCS	:= -I. -I-
DEFS	:= 

#  What object files need building for the program
OBJS	:= mbootpack.o buildimage.o

# Get gcc to generate the dependencies for us.
DEPFLAGS = -Wp,-MD,.$(@F).d
DEPS     = .*.d

mbootpack: $(OBJS)
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $(filter-out %.a, $^)

.PHONY: clean
clean:
	$(RM) mbootpack *.o $(DEPS) bootsect setup bzimage_header.c bin2c

bootsect: bootsect.S
	$(CC) -m32 $(INCS) $(DEFS) -D__MB_ASM -c bootsect.S -o bootsect.o
	$(LD) -m elf_i386 -Ttext 0x0 -s --oformat binary bootsect.o -o $@

setup: setup.S
	$(CC) -m32 $(INCS) $(DEFS) -D__MB_ASM -c setup.S -o setup.o
	$(LD) -m elf_i386 -Ttext 0x0 -s --oformat binary setup.o -o $@

bin2c: bin2c.o 
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $^ 

bzimage_header.c: bootsect setup bin2c
	./bin2c -n 8 -b1 -a bzimage_bootsect bootsect > bzimage_header.c
	./bin2c -n 8 -b1 -a bzimage_setup setup >> bzimage_header.c

buildimage.c: bzimage_header.c
	@

%.o: %.c
	$(HOSTCC) $(DEPFLAGS) $(HOSTCFLAGS) $(INCS) $(DEFS) -c $< -o $@

.PRECIOUS: $(OBJS) $(OBJS:.o=.c) $(DEPS)
.SUFFIXES: 

-include $(DEPS)

#
#  EOF
#
