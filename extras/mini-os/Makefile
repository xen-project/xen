debug ?= y
pae ?= n

XEN_ROOT = ../..
include $(XEN_ROOT)/Config.mk

# Set TARGET_ARCH
override TARGET_ARCH     := $(XEN_TARGET_ARCH)

XEN_INTERFACE_VERSION := 0x00030204

# NB. '-Wcast-qual' is nasty, so I omitted it.
CFLAGS := -fno-builtin -Wall -Werror -Wredundant-decls -Wno-format
CFLAGS += -Wstrict-prototypes -Wnested-externs -Wpointer-arith -Winline
CFLAGS += -D__XEN_INTERFACE_VERSION__=$(XEN_INTERFACE_VERSION)

ASFLAGS = -D__ASSEMBLY__

LDLIBS =  -L. -lminios
LDFLAGS := -N -T minios-$(TARGET_ARCH).lds

# For possible special source directories.
EXTRA_SRC =
# For possible special header directories.
EXTRA_INC =

# Standard name for architecture specific subdirectories.
TARGET_ARCH_DIR = $(TARGET_ARCH)
# This is used for architecture specific links.
ARCH_LINKS =

ifeq ($(TARGET_ARCH),x86_32)
CFLAGS += -m32 -march=i686
LDFLAGS += -m elf_i386
TARGET_ARCH_DIR = x86
EXTRA_INC += $(TARGET_ARCH_DIR)/$(TARGET_ARCH)
EXTRA_SRC += arch/$(EXTRA_INC)
endif

ifeq ($(TARGET_ARCH)$(pae),x86_32y)
CFLAGS  += -DCONFIG_X86_PAE=1
ASFLAGS += -DCONFIG_X86_PAE=1
TARGET_ARCH_DIR = x86
EXTRA_INC += $(TARGET_ARCH_DIR)/$(TARGET_ARCH)
EXTRA_SRC += arch/$(EXTRA_INC)
endif

ifeq ($(TARGET_ARCH),x86_64)
CFLAGS += -m64 -mno-red-zone -fpic -fno-reorder-blocks
CFLAGS += -fno-asynchronous-unwind-tables
LDFLAGS += -m elf_x86_64
TARGET_ARCH_DIR = x86
EXTRA_INC += $(TARGET_ARCH_DIR)/$(TARGET_ARCH)
EXTRA_SRC += arch/$(EXTRA_INC)
endif

ifeq ($(TARGET_ARCH),ia64)
CFLAGS += -mfixed-range=f2-f5,f12-f15,f32-f127 -mconstant-gp
ASFLAGS += -x assembler-with-cpp -Wall
ASFLAGS += -mfixed-range=f2-f5,f12-f15,f32-f127 -fomit-frame-pointer
ASFLAGS += -fno-builtin -fno-common -fno-strict-aliasing -mconstant-gp
ARCH_LINKS = IA64_LINKS		# Special link on ia64 needed
define arch_links
[ -e include/ia64/asm-xsi-offsets.h ] || ln -sf ../../../../xen/include/asm-ia64/asm-xsi-offsets.h include/ia64/asm-xsi-offsets.h
endef
endif

ifeq ($(debug),y)
CFLAGS += -g
else
CFLAGS += -O3
endif

# Add the special header directories to the include paths.
extra_incl := $(foreach dir,$(EXTRA_INC),-Iinclude/$(dir))
override CPPFLAGS := -Iinclude $(CPPFLAGS) -Iinclude/$(TARGET_ARCH_DIR)	$(extra_incl)

TARGET := mini-os

HEAD := $(TARGET_ARCH).o
OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
OBJS += $(patsubst %.c,%.o,$(wildcard lib/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard xenbus/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard console/*.c))
OBJS += $(patsubst %.S,%.o,$(wildcard arch/$(TARGET_ARCH_DIR)/*.S))
OBJS += $(patsubst %.c,%.o,$(wildcard arch/$(TARGET_ARCH_DIR)/*.c))
# For special wanted source directories.
extra_objs := $(foreach dir,$(EXTRA_SRC),$(patsubst %.c,%.o,$(wildcard $(dir)/*.c)))
OBJS += $(extra_objs)
extra_objs := $(foreach dir,$(EXTRA_SRC),$(patsubst %.S,%.o,$(wildcard $(dir)/*.S)))
OBJS += $(extra_objs)

HDRS := $(wildcard include/*.h)
HDRS += $(wildcard include/xen/*.h)
HDRS += $(wildcard include/$(TARGET_ARCH_DIR)/*.h)
# For special wanted header directories.
extra_heads := $(foreach dir,$(EXTRA_INC),$(wildcard $(dir)/*.h))
HDRS += $(extra_heads)

.PHONY: default
default: $(TARGET)

# Create special architecture specific links.
ifneq ($(ARCH_LINKS),)
$(ARCH_LINKS):
	$(arch_links)
endif

.PHONY: links
links:	$(ARCH_LINKS)
	[ -e include/xen ] || ln -sf ../../../xen/include/public include/xen

libminios.a: links $(OBJS) $(HEAD)
	$(AR) r libminios.a $(HEAD) $(OBJS)

$(TARGET): libminios.a $(HEAD)
	$(LD) $(LDFLAGS) $(HEAD) $(LDLIBS) -o $@.elf
	gzip -f -9 -c $@.elf >$@.gz

.PHONY: clean
clean:
	find . -type f -name '*.o' | xargs rm -f
	rm -f *.o *~ core $(TARGET).elf $(TARGET).raw $(TARGET) $(TARGET).gz
	rm -f libminios.a
	find . -type l | xargs rm -f
	rm -f tags TAGS

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
    
.PHONY: tags
tags:
	$(all_sources) | xargs ctags
