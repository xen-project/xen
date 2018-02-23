
-include $(BASEDIR)/include/config/auto.conf

include $(XEN_ROOT)/Config.mk


ifneq ($(origin crash_debug),undefined)
$(error "You must use 'make menuconfig' to enable/disable crash_debug now.")
endif
ifeq ($(origin debug),command line)
$(warning "You must use 'make menuconfig' to enable/disable debug now.")
endif
ifneq ($(origin frame_pointer),undefined)
$(error "You must use 'make menuconfig' to enable/disable frame_pointer now.")
endif
ifneq ($(origin kexec),undefined)
$(error "You must use 'make menuconfig' to enable/disable kexec now.")
endif
ifneq ($(origin lock_profile),undefined)
$(error "You must use 'make menuconfig' to enable/disable lock_profile now.")
endif
ifneq ($(origin perfc),undefined)
$(error "You must use 'make menuconfig' to enable/disable perfc now.")
endif
ifneq ($(origin verbose),undefined)
$(error "You must use 'make menuconfig' to enable/disable verbose now.")
endif

# Set ARCH/SUBARCH appropriately.
override TARGET_SUBARCH  := $(XEN_TARGET_ARCH)
override TARGET_ARCH     := $(shell echo $(XEN_TARGET_ARCH) | \
                              sed -e 's/x86.*/x86/' -e s'/arm\(32\|64\)/arm/g')

TARGET := $(BASEDIR)/xen

# Note that link order matters!
ALL_OBJS-y               += $(BASEDIR)/common/built_in.o
ALL_OBJS-y               += $(BASEDIR)/drivers/built_in.o
ALL_OBJS-y               += $(BASEDIR)/xsm/built_in.o
ALL_OBJS-y               += $(BASEDIR)/arch/$(TARGET_ARCH)/built_in.o
ALL_OBJS-$(CONFIG_CRYPTO)   += $(BASEDIR)/crypto/built_in.o

ifeq ($(CONFIG_DEBUG),y)
CFLAGS += -O1
else
CFLAGS += -O2
endif

ifeq ($(CONFIG_FRAME_POINTER),y)
CFLAGS += -fno-omit-frame-pointer
else
CFLAGS += -fomit-frame-pointer
endif

CFLAGS += -nostdinc -fno-builtin -fno-common
CFLAGS += -Werror -Wredundant-decls -Wno-pointer-arith
CFLAGS += -pipe -g -D__XEN__ -include $(BASEDIR)/include/xen/config.h
CFLAGS += '-D__OBJECT_FILE__="$@"'

ifneq ($(clang),y)
# Clang doesn't understand this command line argument, and doesn't appear to
# have an suitable alternative.  The resulting compiled binary does function,
# but has an excessively large symbol table.
CFLAGS += -Wa,--strip-local-absolute
endif

ifneq ($(max_phys_irqs),)
CFLAGS-y                += -DMAX_PHYS_IRQS=$(max_phys_irqs)
endif

AFLAGS-y                += -D__ASSEMBLY__

# Older clang's built-in assembler doesn't understand .skip with labels:
# https://bugs.llvm.org/show_bug.cgi?id=27369
ifeq ($(clang),y)
$(call as-option-add,CFLAGS,CC,".L0:\n.L1:\n.skip (.L1 - .L0)",,\
                     -no-integrated-as)
endif

ALL_OBJS := $(ALL_OBJS-y)

# Get gcc to generate the dependencies for us.
CFLAGS-y += -MMD -MF $(@D)/.$(@F).d

CFLAGS += $(CFLAGS-y)
# allow extra CFLAGS externally via EXTRA_CFLAGS_XEN_CORE
CFLAGS += $(EXTRA_CFLAGS_XEN_CORE)

# Most CFLAGS are safe for assembly files:
#  -std=gnu{89,99} gets confused by #-prefixed end-of-line comments
#  -flto makes no sense and annoys clang
AFLAGS += $(AFLAGS-y) $(filter-out -std=gnu% -flto,$(CFLAGS))

# LDFLAGS are only passed directly to $(LD)
LDFLAGS += $(LDFLAGS_DIRECT)

LDFLAGS += $(LDFLAGS-y)

include $(BASEDIR)/arch/$(TARGET_ARCH)/Rules.mk

DEPS = .*.d

include Makefile

define gendep
    ifneq ($(1),$(subst /,:,$(1)))
        DEPS += $(dir $(1)).$(notdir $(1)).d
    endif
endef
$(foreach o,$(filter-out %/,$(obj-y)),$(eval $(call gendep,$(o))))

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

ifeq ($(CONFIG_COVERAGE),y)
ifeq ($(clang),y)
    COV_FLAGS := -fprofile-instr-generate -fcoverage-mapping
else
    COV_FLAGS := -fprofile-arcs -ftest-coverage
endif
$(filter-out %.init.o $(nocov-y),$(obj-y) $(obj-bin-y) $(extra-y)): CFLAGS += $(COV_FLAGS)
endif

ifeq ($(CONFIG_UBSAN),y)
$(filter-out %.init.o $(noubsan-y),$(obj-y) $(obj-bin-y) $(extra-y)): CFLAGS += -fsanitize=undefined
endif

ifeq ($(CONFIG_LTO),y)
CFLAGS += -flto
LDFLAGS-$(clang) += -plugin LLVMgold.so
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
ifeq ($(CONFIG_LTO),y)
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
	rm -f *.o *~ core $(DEPS_RM)
_clean_%/: FORCE
	$(MAKE) -f $(BASEDIR)/Rules.mk -C $* clean

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S Makefile
	$(CC) $(AFLAGS) -c $< -o $@

SPECIAL_DATA_SECTIONS := rodata $(foreach a,1 2 4 8 16, \
					    $(foreach w,1 2 4, \
							rodata.str$(w).$(a)) \
					    rodata.cst$(a)) \
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
	$(CPP) $(filter-out -Wa$(comma)%,$(CFLAGS)) $< -o $@

%.s: %.c Makefile
	$(CC) $(filter-out -Wa$(comma)%,$(CFLAGS)) -S $< -o $@

# -std=gnu{89,99} gets confused by # as an end-of-line comment marker
%.s: %.S Makefile
	$(CPP) $(filter-out -Wa$(comma)%,$(AFLAGS)) $< -o $@

-include $(DEPS_INCLUDE)
