
CC := gcc
LD := ld

TARGET_ARCH := $(shell uname -m | sed -e s/i.86/x86_32/)

# NB. '-Wcast-qual' is nasty, so I omitted it.
CFLAGS := -fno-builtin -O3 -Wall -Ih/ -Wredundant-decls -Wno-format
CFLAGS += -Wstrict-prototypes -Wnested-externs -Wpointer-arith -Winline

ifeq ($(TARGET_ARCH),x86_32)
CFLAGS += -m32 -march=i686
LDFLAGS := -m elf_i386
endif

ifeq ($(TARGET_ARCH),x86_64)
CFLAGS += -m64 -mno-red-zone -fpic -fno-reorder-blocks
CFLAGS += -fno-asynchronous-unwind-tables
LDFLAGS := -m elf_x86_64
endif

TARGET := mini-os

OBJS := $(TARGET_ARCH).o
OBJS += $(patsubst %.c,%.o,$(wildcard *.c))
OBJS += $(patsubst %.c,%.o,$(wildcard lib/*.c))

OBJS := $(subst events.o,,$(OBJS))
OBJS := $(subst hypervisor.o,,$(OBJS))
OBJS := $(subst time.o,,$(OBJS))

HDRS := $(wildcard h/*.h)
HDRS += $(wildcard h/xen-public/*.h)

default: $(TARGET)

xen-public:
	[ -e h/xen-public ] || ln -sf ../../../xen/include/public h/xen-public

$(TARGET): xen-public $(OBJS)
	$(LD) -N -T minios-$(TARGET_ARCH).lds $(OBJS) -o $@.elf
	gzip -f -9 -c $@.elf >$@.gz

clean:
	find . -type f -name '*.o' | xargs rm -f
	rm -f *.o *~ core $(TARGET).elf $(TARGET).raw $(TARGET) $(TARGET).gz
	find . -type l | xargs rm -f

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S $(HDRS) Makefile
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@
