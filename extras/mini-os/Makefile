# Common Makefile for mini-os.
#
# Every architecture directory below mini-os/arch has to have a
# Makefile and a arch.mk.
#

pae ?= n

XEN_ROOT = ../..
include $(XEN_ROOT)/Config.mk

XEN_INTERFACE_VERSION := 0x00030205
export XEN_INTERFACE_VERSION

# Set TARGET_ARCH
override TARGET_ARCH := $(XEN_TARGET_ARCH)

# Set mini-os root path, used in mini-os.mk.
MINI-OS_ROOT=$(PWD)
export MINI-OS_ROOT

# Try to find out the architecture family TARGET_ARCH_FAM.
# First check whether x86_... is contained (for x86_32, x86_32y, x86_64).
# If not x86 then use $(TARGET_ARCH) -> for ia64, ...
ifeq ($(findstring x86_,$(TARGET_ARCH)),x86_)
TARGET_ARCH_FAM = x86
else
TARGET_ARCH_FAM = $(TARGET_ARCH)
endif

# The architecture family directory below mini-os.
TARGET_ARCH_DIR := arch/$(TARGET_ARCH_FAM)

# Export these variables for possible use in architecture dependent makefiles.
export TARGET_ARCH
export TARGET_ARCH_DIR
export TARGET_ARCH_FAM

# This is used for architecture specific links.
# This can be overwritten from arch specific rules.
ARCH_LINKS =

# For possible special header directories.
# This can be overwritten from arch specific rules.
EXTRA_INC =

# Special build dependencies.
# Build all after touching this/these file(s) (see minios.mk)
SPEC_DEPENDS = minios.mk

# Include the architecture family's special makerules.
# This must be before include minios.mk!
include $(TARGET_ARCH_DIR)/arch.mk

# Include common mini-os makerules.
include minios.mk

# Define some default flags for linking.
LDLIBS := 
LDFLAGS := 
LDARCHLIB := -L$(TARGET_ARCH_DIR) -l$(ARCH_LIB_NAME)
LDFLAGS_FINAL := -N -T $(TARGET_ARCH_DIR)/minios-$(TARGET_ARCH).lds

# Prefix for global API names. All other symbols are localised before
# linking with EXTRA_OBJS.
GLOBAL_PREFIX := xenos_
EXTRA_OBJS =

TARGET := mini-os

# Subdirectories common to mini-os
SUBDIRS := lib xenbus console

# The common mini-os objects to build.
OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
OBJS += $(patsubst %.c,%.o,$(wildcard lib/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard xenbus/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard console/*.c))


.PHONY: default
default: $(TARGET)

# Create special architecture specific links. The function arch_links
# has to be defined in arch.mk (see include above).
ifneq ($(ARCH_LINKS),)
$(ARCH_LINKS):
	$(arch_links)
endif

.PHONY: links
links:	$(ARCH_LINKS)
	[ -e include/xen ] || ln -sf ../../../xen/include/public include/xen

.PHONY: arch_lib
arch_lib:
	$(MAKE) --directory=$(TARGET_ARCH_DIR) || exit 1;

$(TARGET): links $(OBJS) arch_lib
	$(LD) -r $(LDFLAGS) $(HEAD_OBJ) $(OBJS) $(LDARCHLIB) -o $@.o
	$(OBJCOPY) -w -G $(GLOBAL_PREFIX)* -G _start $@.o $@.o
	$(LD) $(LDFLAGS) $(LDFLAGS_FINAL) $@.o $(EXTRA_OBJS) -o $@
	gzip -f -9 -c $@ >$@.gz

.PHONY: clean arch_clean

arch_clean:
	$(MAKE) --directory=$(TARGET_ARCH_DIR) clean || exit 1;

clean:	arch_clean
	for dir in $(SUBDIRS); do \
		rm -f $$dir/*.o; \
	done
	rm -f *.o *~ core $(TARGET).elf $(TARGET).raw $(TARGET) $(TARGET).gz
	find . -type l | xargs rm -f
	rm -f tags TAGS


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

