
CC := gcc
LD := ld
# Linker should relocate monitor to this address
MONITOR_BASE := 0xE0100000
CFLAGS  := -fno-builtin -O3 -Wall -Ih/

TARGET := mini-os

LOBJS:= lib/malloc.o lib/math.o lib/printf.o lib/string.o 
OBJS := entry.o kernel.o traps.o hypervisor.o mm.o events.o time.o ${LOBJS}

HINTF := h/hypervisor-ifs/hypervisor-if.h
HDRS :=  h/os.h h/types.h h/hypervisor.h h/mm.h h/events.h h/time.h h/lib.h $(HINTF)

default: $(TARGET)

hypervisor-ifs:
	ln -sf ../../../xen/include/hypervisor-ifs h/hypervisor-ifs

$(TARGET): hypervisor-ifs head.o $(OBJS)
	# Image will load at 0xC0000000. First bytes from head.o
	#$(LD) -N -Ttext 0xC0000000 head.o $(OBJS) -o $@.elf
	$(LD) -N -T minios.lds head.o $(OBJS) -o $@.elf
	# Guest OS header -- first 8 bytes are identifier 'XenoGues'.
	echo -e -n 'XenoGues' >$@ 
	# Guest OS header -- next 4 bytes are load address (0xC0000000).
	echo -e -n '\000\000\000\300' >>$@
	# Create a raw bag of bytes from the ELF image.
	objcopy -O binary -R .note -R .comment $@.elf $@.raw
	# Guest OS header is immediately followed by raw OS image.
	cat $@.raw >>$@
	gzip -f -9 -c $@ >$@.gz

clean:
	find . -type f -name '*.o' | xargs rm -f
	rm -f *.o *~ core $(TARGET).elf $(TARGET).raw $(TARGET) $(TARGET).gz
	find . -type l | xargs rm -f

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S $(HDRS) Makefile
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@

