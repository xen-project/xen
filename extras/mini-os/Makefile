
CC := gcc
LD := ld
# Linker should relocate monitor to this address
MONITOR_BASE := 0xE0100000
CFLAGS  := -fno-builtin -O3 -Wall -Ih/

TARGET := image.final

LOBJS:= lib/malloc.o lib/math.o lib/printf.o lib/string.o 
OBJS := entry.o kernel.o traps.o hypervisor.o mm.o events.o time.o ${LOBJS}

HINTF := h/hypervisor-ifs/hypervisor-if.h
HDRS :=  h/os.h h/types.h h/hypervisor.h h/mm.h h/events.h h/time.h h/lib.h $(HINTF)

default: $(TARGET)

$(TARGET): head.o $(OBJS)
	# Image will load at 0xC0000000. First bytes from head.o
	#$(LD) -N -Ttext 0xC0000000 head.o $(OBJS) -o image.elf
	$(LD) -N -T vmlinux.lds head.o $(OBJS) -o image.elf
	# Guest OS header -- first 8 bytes are identifier 'XenoGues'.
	echo -e -n 'XenoGues' >$@ 
	# Guest OS header -- next 4 bytes are load address (0xC0000000).
	echo -e -n '\000\000\000\300' >>$@
	# Create a raw bag of bytes from the ELF image.
	objcopy -O binary -R .note -R .comment image.elf image.raw
	# Guest OS header is immediately followed by raw OS image.
	cat image.raw >>$@
	#gzip -f -9 $@

clean:
	rm -f *.o *~ core image.elf image.raw image.final image.final.gz

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S $(HDRS) Makefile
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@

