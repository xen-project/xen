debug ?= y
pae ?= n

include $(CURDIR)/../../Config.mk

# Set TARGET_ARCH
override TARGET_ARCH     := $(XEN_TARGET_ARCH)

# NB. '-Wcast-qual' is nasty, so I omitted it.
CFLAGS := -fno-builtin -Wall -Werror -Wredundant-decls -Wno-format
CFLAGS += -Wstrict-prototypes -Wnested-externs -Wpointer-arith -Winline

override CPPFLAGS := -Iinclude $(CPPFLAGS)
ASFLAGS = -D__ASSEMBLY__

LDFLAGS := -N -T minios-$(TARGET_ARCH).lds

ifeq ($(TARGET_ARCH),x86_32)
CFLAGS += -m32 -march=i686
LDFLAGS += -m elf_i386
endif

ifeq ($(TARGET_ARCH)$(pae),x86_32y)
CFLAGS  += -DCONFIG_X86_PAE=1
ASFLAGS += -DCONFIG_X86_PAE=1
endif

ifeq ($(TARGET_ARCH),x86_64)
CFLAGS += -m64 -mno-red-zone -fpic -fno-reorder-blocks
CFLAGS += -fno-asynchronous-unwind-tables
LDFLAGS += -m elf_x86_64
endif

ifeq ($(debug),y)
CFLAGS += -g
else
CFLAGS += -O3
endif

TARGET := mini-os

HEAD := $(TARGET_ARCH).o
OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
OBJS += $(patsubst %.c,%.o,$(wildcard lib/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard xenbus/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard console/*.c))

HDRS := $(wildcard include/*.h)
HDRS += $(wildcard include/xen/*.h)

.PHONY: default
default: $(TARGET)

.PHONY: links
links:
	[ -e include/xen ] || ln -sf ../../../xen/include/public include/xen

libminios.a: $(OBJS) $(HEAD)
	ar r libminios.a $(HEAD) $(OBJS)

$(TARGET): links libminios.a $(HEAD)
	$(LD) $(LDFLAGS) $(HEAD) -L. -lminios -o $@.elf
	gzip -f -9 -c $@.elf >$@.gz

.PHONY: clean
clean:
	find . -type f -name '*.o' | xargs rm -f
	rm -f *.o *~ core $(TARGET).elf $(TARGET).raw $(TARGET) $(TARGET).gz
	rm -f libminios.a
	find . -type l | xargs rm -f

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

%.o: %.S $(HDRS) Makefile
	$(CC) $(ASFLAGS) $(CPPFLAGS) -c $< -o $@

define all_sources
     ( find . -follow -name SCCS -prune -o -name '*.[chS]' -print )
endef

.PHONY: cscope
cscope:
	$(all_sources) > cscope.files
	cscope -k -b -q

