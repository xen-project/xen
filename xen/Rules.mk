
#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#
verbose       ?= n
perfc         ?= n
perfc_arrays  ?= n
lock_profile  ?= n
crash_debug   ?= n
gdbsx         ?= n
frame_pointer ?= n

XEN_ROOT=$(BASEDIR)/..
include $(XEN_ROOT)/Config.mk

# Hardcoded configuration implications and dependencies.
# Do this is a neater way if it becomes unwieldy.
ifeq ($(debug),y)
verbose       := y
frame_pointer := y
else
CFLAGS += -DNDEBUG
endif
ifeq ($(perfc_arrays),y)
perfc := y
endif

# Set ARCH/SUBARCH appropriately.
override TARGET_SUBARCH  := $(XEN_TARGET_ARCH)
override TARGET_ARCH     := $(shell echo $(XEN_TARGET_ARCH) | \
                              sed -e 's/x86.*/x86/')

TARGET := $(BASEDIR)/xen

include $(BASEDIR)/arch/$(TARGET_ARCH)/Rules.mk

# Note that link order matters!
ALL_OBJS-y               += $(BASEDIR)/common/built_in.o
ALL_OBJS-y               += $(BASEDIR)/drivers/built_in.o
ALL_OBJS-y               += $(BASEDIR)/xsm/built_in.o
ALL_OBJS-y               += $(BASEDIR)/arch/$(TARGET_ARCH)/built_in.o
ALL_OBJS-$(x86)          += $(BASEDIR)/crypto/built_in.o

CFLAGS-y                += -g -D__XEN__
CFLAGS-$(XSM_ENABLE)    += -DXSM_ENABLE
CFLAGS-$(FLASK_ENABLE)  += -DFLASK_ENABLE -DXSM_MAGIC=0xf97cff8c
CFLAGS-$(FLASK_ENABLE)  += -DFLASK_DEVELOP -DFLASK_BOOTPARAM -DFLASK_AVC_STATS
CFLAGS-$(ACM_SECURITY)  += -DACM_SECURITY -DXSM_MAGIC=0xbcde0100
CFLAGS-$(verbose)       += -DVERBOSE
CFLAGS-$(crash_debug)   += -DCRASH_DEBUG
CFLAGS-$(perfc)         += -DPERF_COUNTERS
CFLAGS-$(perfc_arrays)  += -DPERF_ARRAYS
CFLAGS-$(lock_profile)  += -DLOCK_PROFILE
CFLAGS-$(frame_pointer) += -fno-omit-frame-pointer -DCONFIG_FRAME_POINTER
CFLAGS-$(gdbsx)         += -DXEN_GDBSX_CONFIG

ifneq ($(max_phys_cpus),)
CFLAGS-y                += -DMAX_PHYS_CPUS=$(max_phys_cpus)
endif
ifneq ($(max_phys_irqs),)
CFLAGS-y                += -DMAX_PHYS_IRQS=$(max_phys_irqs)
endif

AFLAGS-y                += -D__ASSEMBLY__

ALL_OBJS := $(ALL_OBJS-y)

# Get gcc to generate the dependencies for us.
CFLAGS-y += -MMD -MF .$(@F).d
DEPS = .*.d

CFLAGS += $(CFLAGS-y)

# Most CFLAGS are safe for assembly files:
#  -std=gnu{89,99} gets confused by #-prefixed end-of-line comments
AFLAGS += $(AFLAGS-y) $(filter-out -std=gnu%,$(CFLAGS))

# LDFLAGS are only passed directly to $(LD)
LDFLAGS += $(LDFLAGS_DIRECT)

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
	rm -f *.o *~ core $(DEPS)
_clean_%/: FORCE
	$(MAKE) -f $(BASEDIR)/Rules.mk -C $* clean

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S Makefile
	$(CC) $(AFLAGS) -c $< -o $@

%.i: %.c Makefile
	$(CPP) $(CFLAGS) $< -o $@

# -std=gnu{89,99} gets confused by # as an end-of-line comment marker
%.s: %.S Makefile
	$(CPP) $(AFLAGS) $< -o $@

-include $(DEPS)
