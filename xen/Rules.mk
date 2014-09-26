
#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#
verbose       ?= n
perfc         ?= n
perfc_arrays  ?= n
lock_profile  ?= n
crash_debug   ?= n
frame_pointer ?= n
lto           ?= n

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
                              sed -e 's/x86.*/x86/' -e s'/arm\(32\|64\)/arm/g')

TARGET := $(BASEDIR)/xen

include $(BASEDIR)/arch/$(TARGET_ARCH)/Rules.mk

# Note that link order matters!
ALL_OBJS-y               += $(BASEDIR)/common/built_in.o
ALL_OBJS-y               += $(BASEDIR)/drivers/built_in.o
ALL_OBJS-y               += $(BASEDIR)/xsm/built_in.o
ALL_OBJS-y               += $(BASEDIR)/arch/$(TARGET_ARCH)/built_in.o
ALL_OBJS-$(x86)          += $(BASEDIR)/crypto/built_in.o

CFLAGS += -fno-builtin -fno-common
CFLAGS += -Werror -Wredundant-decls -Wno-pointer-arith
CFLAGS += -pipe -g -D__XEN__ -include $(BASEDIR)/include/xen/config.h
CFLAGS += -nostdinc

CFLAGS-$(XSM_ENABLE)    += -DXSM_ENABLE
CFLAGS-$(FLASK_ENABLE)  += -DFLASK_ENABLE
CFLAGS-$(verbose)       += -DVERBOSE
CFLAGS-$(crash_debug)   += -DCRASH_DEBUG
CFLAGS-$(perfc)         += -DPERF_COUNTERS
CFLAGS-$(perfc_arrays)  += -DPERF_ARRAYS
CFLAGS-$(lock_profile)  += -DLOCK_PROFILE
CFLAGS-$(HAS_ACPI)      += -DHAS_ACPI
CFLAGS-$(HAS_GDBSX)     += -DHAS_GDBSX
CFLAGS-$(HAS_PASSTHROUGH) += -DHAS_PASSTHROUGH
CFLAGS-$(HAS_DEVICE_TREE) += -DHAS_DEVICE_TREE
CFLAGS-$(HAS_MEM_ACCESS)  += -DHAS_MEM_ACCESS
CFLAGS-$(HAS_MEM_PAGING)  += -DHAS_MEM_PAGING
CFLAGS-$(HAS_MEM_SHARING) += -DHAS_MEM_SHARING
CFLAGS-$(HAS_PCI)       += -DHAS_PCI
CFLAGS-$(HAS_IOPORTS)   += -DHAS_IOPORTS
CFLAGS-$(HAS_PDX)       += -DHAS_PDX
CFLAGS-$(frame_pointer) += -fno-omit-frame-pointer -DCONFIG_FRAME_POINTER

ifneq ($(max_phys_cpus),)
CFLAGS-y                += -DMAX_PHYS_CPUS=$(max_phys_cpus)
endif
ifneq ($(max_phys_irqs),)
CFLAGS-y                += -DMAX_PHYS_IRQS=$(max_phys_irqs)
endif

AFLAGS-y                += -D__ASSEMBLY__ -include $(BASEDIR)/include/xen/config.h

# Clang's built-in assembler can't handle .code16/.code32/.code64 yet
AFLAGS-$(clang)         += -no-integrated-as

ALL_OBJS := $(ALL_OBJS-y)

# Get gcc to generate the dependencies for us.
CFLAGS-y += -MMD -MF .$(@F).d
DEPS = .*.d

CFLAGS += $(CFLAGS-y)

# Most CFLAGS are safe for assembly files:
#  -std=gnu{89,99} gets confused by #-prefixed end-of-line comments
#  -flto makes no sense and annoys clang
AFLAGS += $(AFLAGS-y) $(filter-out -std=gnu%,$(filter-out -flto,$(CFLAGS)))

# LDFLAGS are only passed directly to $(LD)
LDFLAGS += $(LDFLAGS_DIRECT)

LDFLAGS += $(LDFLAGS-y)

include Makefile

# Ensure each subdirectory has exactly one trailing slash.
subdir-n := $(patsubst %,%/,$(patsubst %/,%,$(subdir-n) $(subdir-)))
subdir-y := $(patsubst %,%/,$(patsubst %/,%,$(subdir-y)))

# Add explicitly declared subdirectories to the object lists.
obj-y += $(patsubst %/,%/built_in.o,$(subdir-y))

# Add implicitly declared subdirectories (in the object lists) to the
# subdirectory list, and rewrite the object-list entry.
subdir-y += $(filter %/,$(obj-y))
obj-y    := $(patsubst %/,%/built-in.o,$(obj-y))

subdir-all := $(subdir-y) $(subdir-n)

$(filter %.init.o,$(obj-y) $(obj-bin-y) $(extra-y)): CFLAGS += -DINIT_SECTIONS_ONLY

$(obj-$(coverage)): CFLAGS += -fprofile-arcs -ftest-coverage -DTEST_COVERAGE

ifeq ($(lto),y)
# Would like to handle all object files as bitcode, but objects made from
# pure asm are in a different format and have to be collected separately.
# Mirror the directory tree, collecting them as built_in_bin.o.
# If there are no binary objects in a given directory, make a dummy .o
obj-bin-y += $(patsubst %/built_in.o,%/built_in_bin.o,$(filter %/built_in.o,$(obj-y)))
else
# For a non-LTO build, bundle obj-bin targets in with the normal objs.
obj-y += $(obj-bin-y)
obj-bin-y :=
endif

# Always build obj-bin files as binary even if they come from C source. 
$(obj-bin-y): CFLAGS := $(filter-out -flto,$(CFLAGS))

built_in.o: $(obj-y)
ifeq ($(obj-y),)
	$(CC) $(CFLAGS) -c -x c /dev/null -o $@
else
ifeq ($(lto),y)
	$(LD_LTO) -r -o $@ $^
else
	$(LD) $(LDFLAGS) -r -o $@ $^
endif
endif

built_in_bin.o: $(obj-bin-y)
ifeq ($(obj-bin-y),)
	$(CC) $(AFLAGS) -c -x assembler /dev/null -o $@
else
	$(LD) $(LDFLAGS) -r -o $@ $^
endif

# Force execution of pattern rules (for which PHONY cannot be directly used).
.PHONY: FORCE
FORCE:

%/built_in.o: FORCE
	$(MAKE) -f $(BASEDIR)/Rules.mk -C $* built_in.o

%/built_in_bin.o: FORCE
	$(MAKE) -f $(BASEDIR)/Rules.mk -C $* built_in_bin.o

.PHONY: clean
clean:: $(addprefix _clean_, $(subdir-all))
	rm -f *.o *~ core $(DEPS)
_clean_%/: FORCE
	$(MAKE) -f $(BASEDIR)/Rules.mk -C $* clean

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S Makefile
	$(CC) $(AFLAGS) -c $< -o $@

SPECIAL_DATA_SECTIONS := rodata $(foreach n,1 2 4 8,rodata.str1.$(n)) \
			 $(foreach r,rel rel.ro,data.$(r).local)

$(filter %.init.o,$(obj-y) $(obj-bin-y) $(extra-y)): %.init.o: %.o Makefile
	$(OBJDUMP) -h $< | sed -n '/[0-9]/{s,00*,0,g;p;}' | while read idx name sz rest; do \
		case "$$name" in \
		.*.local) ;; \
		.text|.text.*|.data|.data.*|.bss) \
			test $$sz != 0 || continue; \
			echo "Error: size of $<:$$name is 0x$$sz" >&2; \
			exit $$(expr $$idx + 1);; \
		esac; \
	done
	$(OBJCOPY) $(foreach s,$(SPECIAL_DATA_SECTIONS),--rename-section .$(s)=.init.$(s)) $< $@

%.i: %.c Makefile
	$(CPP) $(CFLAGS) $< -o $@

%.s: %.c Makefile
	$(CC) $(CFLAGS) -S $< -o $@

# -std=gnu{89,99} gets confused by # as an end-of-line comment marker
%.s: %.S Makefile
	$(CPP) $(AFLAGS) $< -o $@

-include $(DEPS)
