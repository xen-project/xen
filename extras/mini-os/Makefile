
CC := gcc
LD := ld

# Linker should relocate monitor to this address
MONITOR_BASE := 0xE0100000

# NB. '-Wcast-qual' is nasty, so I omitted it.
CFLAGS := -fno-builtin -O3 -Wall -Ih/ -Wredundant-decls
CFLAGS += -Wstrict-prototypes -Wnested-externs -Wpointer-arith -Winline -ansi

TARGET := mini-os

LOBJS := lib/malloc.o lib/math.o lib/printf.o lib/string.o 
OBJS  := entry.o kernel.o traps.o hypervisor.o mm.o events.o time.o ${LOBJS}

HINTF := h/xen-public/xen.h
HDRS  :=  h/os.h h/types.h h/hypervisor.h h/mm.h h/events.h h/time.h h/lib.h
HDRS  += $(HINTF)

default: $(TARGET)

xen-public:
	[ -e h/xen-public] || ln -sf ../../../xen/include/public h/xen-public

$(TARGET): xen-public head.o $(OBJS)
	$(LD) -N -T minios.lds head.o $(OBJS) -o $@.elf
	objcopy -R .note -R .comment $@.elf $@
	gzip -f -9 -c $@ >$@.gz

clean:
	find . -type f -name '*.o' | xargs rm -f
	rm -f *.o *~ core $(TARGET).elf $(TARGET).raw $(TARGET) $(TARGET).gz
	find . -type l | xargs rm -f

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S $(HDRS) Makefile
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@

