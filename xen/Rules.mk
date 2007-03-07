
#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#
verbose     ?= n
perfc       ?= n
perfc_arrays?= n
crash_debug ?= n

XEN_ROOT=$(BASEDIR)/..
include $(XEN_ROOT)/Config.mk

# Hardcoded configuration implications and dependencies.
# Do this is a neater way if it becomes unwieldy.
ifeq ($(debug),y)
verbose := y
endif
ifeq ($(perfc_arrays),y)
perfc := y
endif

# Set ARCH/SUBARCH appropriately.
override COMPILE_SUBARCH := $(XEN_COMPILE_ARCH)
override TARGET_SUBARCH  := $(XEN_TARGET_ARCH)
override COMPILE_ARCH    := $(shell echo $(XEN_COMPILE_ARCH) | \
                              sed -e 's/x86.*/x86/' \
                                  -e 's/powerpc.*/powerpc/')
override TARGET_ARCH     := $(shell echo $(XEN_TARGET_ARCH) | \
                              sed -e 's/x86.*/x86/' \
                                  -e 's/powerpc.*/powerpc/')

TARGET := $(BASEDIR)/xen

HDRS := $(wildcard $(BASEDIR)/include/xen/*.h)
HDRS += $(wildcard $(BASEDIR)/include/public/*.h)
HDRS += $(wildcard $(BASEDIR)/include/compat/*.h)
HDRS += $(wildcard $(BASEDIR)/include/asm-$(TARGET_ARCH)/*.h)
HDRS += $(wildcard $(BASEDIR)/include/asm-$(TARGET_ARCH)/$(TARGET_SUBARCH)/*.h)

include $(BASEDIR)/arch/$(TARGET_ARCH)/Rules.mk

# Do not depend on auto-generated header files.
AHDRS := $(filter-out %/include/xen/compile.h,$(HDRS))
HDRS  := $(filter-out %/asm-offsets.h,$(AHDRS))

# Note that link order matters!
ALL_OBJS-y               += $(BASEDIR)/common/built_in.o
ALL_OBJS-y               += $(BASEDIR)/drivers/built_in.o
ALL_OBJS-$(ACM_SECURITY) += $(BASEDIR)/acm/built_in.o
ALL_OBJS-y               += $(BASEDIR)/arch/$(TARGET_ARCH)/built_in.o

CFLAGS-y               += -g -D__XEN__
CFLAGS-$(ACM_SECURITY) += -DACM_SECURITY
CFLAGS-$(verbose)      += -DVERBOSE
CFLAGS-$(crash_debug)  += -DCRASH_DEBUG
CFLAGS-$(perfc)        += -DPERF_COUNTERS
CFLAGS-$(perfc_arrays) += -DPERF_ARRAYS

ifneq ($(max_phys_cpus),)
CFLAGS-y               += -DMAX_PHYS_CPUS=$(max_phys_cpus)
endif

AFLAGS-y               += -D__ASSEMBLY__

ALL_OBJS := $(ALL_OBJS-y)

CFLAGS   := $(strip $(CFLAGS) $(CFLAGS-y))

# Most CFLAGS are safe for assembly files:
#  -std=gnu{89,99} gets confused by #-prefixed end-of-line comments
AFLAGS   := $(strip $(AFLAGS) $(AFLAGS-y))
AFLAGS   += $(patsubst -std=gnu%,,$(CFLAGS))

# LDFLAGS are only passed directly to $(LD)
LDFLAGS  := $(strip $(LDFLAGS) $(LDFLAGS_DIRECT))

include Makefile

# Ensure each subdirectory has exactly one trailing slash.
subdir-n := $(patsubst %,%/,$(patsubst %/,%,$(subdir-n)))
subdir-y := $(patsubst %,%/,$(patsubst %/,%,$(subdir-y)))

# Add explicitly declared subdirectories to the object list.
obj-y += $(patsubst %/,%/built_in.o,$(subdir-y))

# Add implicitly declared subdirectories (in the object list) to the
# subdirectory list, and rewrite the object-list entry.
subdir-y += $(filter %/,$(obj-y))
obj-y    := $(patsubst %/,%/built-in.o,$(obj-y))

subdir-all := $(subdir-y) $(subdir-n)

built_in.o: $(obj-y)
	$(LD) $(LDFLAGS) -r -o $@ $^

# Force execution of pattern rules (for which PHONY cannot be directly used).
.PHONY: FORCE
FORCE:

%/built_in.o: FORCE
	$(MAKE) -f $(BASEDIR)/Rules.mk -C $* built_in.o

.PHONY: clean
clean:: $(addprefix _clean_, $(subdir-all))
	rm -f *.o *~ core
_clean_%/: FORCE
	$(MAKE) -f $(BASEDIR)/Rules.mk -C $* clean

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S $(AHDRS) Makefile
	$(CC) $(AFLAGS) -c $< -o $@

%.i: %.c $(HDRS) Makefile
	$(CPP) $(CFLAGS) $< -o $@

# -std=gnu{89,99} gets confused by # as an end-of-line comment marker
%.s: %.S $(AHDRS) Makefile
	$(CPP) $(AFLAGS) $< -o $@
