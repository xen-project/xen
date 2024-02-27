#
# See docs/misc/xen-makefiles/makefiles.rst on variables that can be used in
# Makefile and are consumed by Rules.mk
#

ifndef obj
$(warning kbuild: Rules.mk is included improperly)
endif

src := $(obj)

# shortcuts
srcdir := $(srctree)/$(src)

PHONY := __build
__build:

ifneq ($(firstword $(subst /, ,$(obj))),tools)
include $(objtree)/include/config/auto.conf
endif

include $(XEN_ROOT)/Config.mk
include $(srctree)/scripts/Kbuild.include

# Initialise some variables
obj-y :=
lib-y :=
targets :=
subdir-y :=
CFLAGS-y :=
AFLAGS-y :=
nocov-y :=
noubsan-y :=

SPECIAL_DATA_SECTIONS := rodata $(foreach a,1 2 4 8 16, \
                                            $(foreach w,1 2 4, \
                                                        rodata.str$(w).$(a)) \
                                            rodata.cst$(a)) \
                         $(foreach r,rel rel.ro,data.$(r).local)

# The filename build.mk has precedence over Makefile
include $(firstword $(wildcard $(srcdir)/build.mk) $(srcdir)/Makefile)

# Linking
# ---------------------------------------------------------------------------

quiet_cmd_ld = LD      $@
cmd_ld = $(LD) $(XEN_LDFLAGS) -r -o $@ $(filter-out %.a,$(real-prereqs)) \
               --start-group $(filter %.a,$(real-prereqs)) --end-group

# Archive
# ---------------------------------------------------------------------------

quiet_cmd_ar = AR      $@
cmd_ar = rm -f $@; $(AR) cr $@ $(real-prereqs)

# Objcopy
# ---------------------------------------------------------------------------

quiet_cmd_objcopy = OBJCOPY $@
cmd_objcopy = $(OBJCOPY) $(OBJCOPYFLAGS) $< $@

# binfile
# use e.g. $(call if_changed,binfile,binary-file varname)
quiet_cmd_binfile = BINFILE $@
cmd_binfile = $(SHELL) $(srctree)/tools/binfile $(BINFILE_FLAGS) $@ $(2)

# Figure out what we need to build from the various variables
# ===========================================================================

# Libraries are always collected in one lib file.
# Filter out objects already built-in
lib-y := $(filter-out $(obj-y), $(sort $(lib-y)))

# Subdirectories we need to descend into
subdir-y := $(sort $(subdir-y) $(patsubst %/,%,$(filter %/, $(obj-y))))

# Handle objects in subdirs
# - if we encounter foo/ in $(obj-y), replace it by foo/built_in.o
ifdef need-builtin
obj-y    := $(patsubst %/, %/built_in.o, $(obj-y))
else
obj-y    := $(filter-out %/, $(obj-y))
endif

# hostprogs-always-y += foo
# ... is a shorthand for
# hostprogs-y += foo
# always-y  += foo
hostprogs-y += $(hostprogs-always-y)
always-y += $(hostprogs-always-y)

# Add subdir path

extra-y         := $(addprefix $(obj)/,$(extra-y))
always-y        := $(addprefix $(obj)/,$(always-y))
targets         := $(addprefix $(obj)/,$(targets))
lib-y           := $(addprefix $(obj)/,$(lib-y))
obj-y           := $(addprefix $(obj)/,$(obj-y))
obj-bin-y       := $(addprefix $(obj)/,$(obj-bin-y))
subdir-y        := $(addprefix $(obj)/,$(subdir-y))
nocov-y         := $(addprefix $(obj)/,$(nocov-y))
noubsan-y       := $(addprefix $(obj)/,$(noubsan-y))

# Do not include hostprogs rules unless needed.
# $(sort ...) is used here to remove duplicated words and excessive spaces.
hostprogs-y := $(sort $(hostprogs-y))
ifneq ($(hostprogs-y),)
include scripts/Makefile.host
endif

# subdir-builtin may contain duplications. Use $(sort ...)
subdir-builtin := $(sort $(filter %/built_in.o, $(obj-y)))

targets-for-builtin := $(extra-y)

ifneq ($(strip $(lib-y)),)
    targets-for-builtin += $(obj)/lib.a
endif

ifdef need-builtin
    targets-for-builtin += $(obj)/built_in.o
    ifneq ($(strip $(obj-bin-y)),)
        ifeq ($(CONFIG_LTO),y)
            targets-for-builtin += $(obj)/built_in_bin.o
        endif
    endif
endif

targets += $(targets-for-builtin)

$(filter %.init.o,$(obj-y) $(obj-bin-y) $(extra-y)): CFLAGS-y += -DINIT_SECTIONS_ONLY

non-init-objects = $(filter-out %.init.o, $(obj-y) $(obj-bin-y) $(extra-y))

ifeq ($(CONFIG_COVERAGE),y)
ifeq ($(CONFIG_CC_IS_CLANG),y)
    COV_FLAGS := -fprofile-instr-generate -fcoverage-mapping
else
    COV_FLAGS := -fprofile-arcs -ftest-coverage
endif

# Reset COV_FLAGS in cases where an objects has another one as prerequisite
$(nocov-y) $(filter %.init.o, $(obj-y) $(obj-bin-y) $(extra-y)): \
    COV_FLAGS :=

$(non-init-objects): _c_flags += $(COV_FLAGS)
endif

ifeq ($(CONFIG_UBSAN),y)
# Any -fno-sanitize= options need to come after any -fsanitize= options
UBSAN_FLAGS := $(filter-out -fno-%,$(CFLAGS_UBSAN)) $(filter -fno-%,$(CFLAGS_UBSAN))

# Reset UBSAN_FLAGS in cases where an objects has another one as prerequisite
$(noubsan-y) $(filter %.init.o, $(obj-y) $(obj-bin-y) $(extra-y)): \
    UBSAN_FLAGS :=

$(non-init-objects): _c_flags += $(UBSAN_FLAGS)
endif

ifeq ($(CONFIG_LTO),y)
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
$(obj-bin-y): XEN_CFLAGS := $(filter-out -flto,$(XEN_CFLAGS))

# To be use with e.g. $(a_flags) or $(c_flags) to produce CPP flags
cpp_flags = $(filter-out -Wa$(comma)% -flto,$(1))

# Calculation of flags, first the generic flags, then the arch specific flags,
# and last the flags modified for a target or a directory.

c_flags = -MMD -MP -MF $(depfile) $(XEN_CFLAGS)
a_flags = -MMD -MP -MF $(depfile) $(XEN_AFLAGS)

include $(srctree)/arch/$(SRCARCH)/Rules.mk

c_flags += $(_c_flags)
a_flags += $(_c_flags)

c_flags += $(CFLAGS-y)
a_flags += $(CFLAGS-y) $(AFLAGS-y)

quiet_cmd_cc_builtin = CC      $@
cmd_cc_builtin = \
    $(CC) $(XEN_CFLAGS) -c -x c /dev/null -o $@

# To build objects in subdirs, we need to descend into the directories
$(subdir-builtin): $(obj)/%/built_in.o: $(obj)/% ;

quiet_cmd_ld_builtin = LD      $@
ifeq ($(CONFIG_LTO),y)
cmd_ld_builtin = \
    $(LD_LTO) -r -o $@ $(real-prereqs)
else
cmd_ld_builtin = \
    $(LD) $(XEN_LDFLAGS) -r -o $@ $(real-prereqs)
endif

$(obj)/built_in.o: $(obj-y) FORCE
	$(call if_changed,$(if $(strip $(obj-y)),ld_builtin,cc_builtin))

$(obj)/lib.a: $(lib-y) FORCE
	$(call if_changed,ar)

targets += $(filter-out $(subdir-builtin), $(obj-y))
targets += $(lib-y) $(MAKECMDGOALS)

$(obj)/built_in_bin.o: $(obj-bin-y)
ifeq ($(strip $(obj-bin-y)),)
	$(CC) $(a_flags) -c -x assembler /dev/null -o $@
else
	$(LD) $(XEN_LDFLAGS) -r -o $@ $(filter $(obj-bin-y),$^)
endif

# Force execution of pattern rules (for which PHONY cannot be directly used).
PHONY += FORCE
FORCE:

quiet_cmd_cc_o_c = CC      $@
ifeq ($(CONFIG_ENFORCE_UNIQUE_SYMBOLS),y)
    cmd_cc_o_c = $(CC) $(c_flags) -c $< -o $(dot-target).tmp -MQ $@
    ifneq ($(CONFIG_CC_IS_CLANG)$(call clang-ifversion,-lt,600,y),yy)
        rel-path = $(patsubst $(abs_srctree)/%,%,$(call realpath,$(1)))
        cmd_objcopy_fix_sym = \
           $(OBJCOPY) --redefine-sym $(<F)=$(call rel-path,$<) $(dot-target).tmp $@ && rm -f $(dot-target).tmp
    else
        cmd_objcopy_fix_sym = mv -f $(dot-target).tmp $@
    endif
else
    cmd_cc_o_c = $(CC) $(c_flags) -c $< -o $@
endif

define rule_cc_o_c
    $(call cmd_and_fixdep,cc_o_c)
    $(call cmd,objcopy_fix_sym)
endef

$(obj)/%.o: $(src)/%.c FORCE
	$(call if_changed_rule,cc_o_c)

quiet_cmd_cc_o_S = CC      $@
cmd_cc_o_S = $(CC) $(a_flags) -c $< -o $@

$(obj)/%.o: $(src)/%.S FORCE
	$(call if_changed_dep,cc_o_S)


quiet_cmd_obj_init_o = INIT_O  $@
define cmd_obj_init_o
    $(OBJDUMP) -h $< | while read idx name sz rest; do \
        case "$$name" in \
        .*.local) ;; \
        .text|.text.*|.data|.data.*|.bss|.bss.*) \
            test $$(echo $$sz | sed 's,00*,0,') != 0 || continue; \
            echo "Error: size of $<:$$name is 0x$$sz" >&2; \
            exit $$(expr $$idx + 1);; \
        esac; \
    done || exit $$?; \
    $(OBJCOPY) $(foreach s,$(SPECIAL_DATA_SECTIONS),--rename-section .$(s)=.init.$(s)) $< $@
endef

$(filter %.init.o,$(obj-y) $(obj-bin-y) $(extra-y)): $(obj)/%.init.o: $(obj)/%.o FORCE
	$(call if_changed,obj_init_o)

quiet_cmd_cpp_i_c = CPP     $@
cmd_cpp_i_c = $(CPP) $(call cpp_flags,$(c_flags)) -MQ $@ -o $@ $<

quiet_cmd_cpp_i_S = CPP     $@
cmd_cpp_i_S = $(CPP) $(call cpp_flags,$(a_flags)) -MQ $@ -o $@ $<

quiet_cmd_cc_s_c = CC      $@
cmd_cc_s_c = $(CC) $(filter-out -Wa$(comma)%,$(c_flags)) -S $< -o $@

quiet_cmd_cpp_s_S = CPP     $@
cmd_cpp_s_S = $(CPP) $(call cpp_flags,$(a_flags)) -MQ $@ -o $@ $<

$(obj)/%.i: $(src)/%.c FORCE
	$(call if_changed_dep,cpp_i_c)

$(obj)/%.i: $(src)/%.S FORCE
	$(call if_changed_dep,cpp_i_S)

$(obj)/%.s: $(src)/%.c FORCE
	$(call if_changed_dep,cc_s_c)

$(obj)/%.s: $(src)/%.S FORCE
	$(call if_changed_dep,cpp_s_S)

# Linker scripts, .lds.S -> .lds
quiet_cmd_cpp_lds_S = LDS     $@
cmd_cpp_lds_S = $(CPP) -P $(call cpp_flags,$(a_flags)) -DLINKER_SCRIPT -MQ $@ -o $@ $<

targets := $(filter-out $(PHONY), $(targets))

# Add intermediate targets:
# When building objects with specific suffix patterns, add intermediate
# targets that the final targets are derived from.
intermediate_targets = $(foreach sfx, $(2), \
				$(patsubst %$(strip $(1)),%$(sfx), \
					$(filter %$(strip $(1)), $(targets))))
# %.init.o <- %.o
# %.lex.o <- %.lex.c <- %.l
# %.tab.o <- %.tab.[ch] <- %.y
targets += $(call intermediate_targets, .init.o, .o) \
	   $(call intermediate_targets, .lex.o, .lex.c) \
	   $(call intermediate_targets, .tab.o, .tab.c .tab.h)

# Build
# ---------------------------------------------------------------------------

__build: $(targets-for-builtin) $(subdir-y) $(always-y)
	@:

# Descending
# ---------------------------------------------------------------------------

PHONY += $(subdir-y)
$(subdir-y):
	$(Q)$(MAKE) $(build)=$@ need-builtin=$(if $(filter $@/built_in.o, $(subdir-builtin)),1)

# Read all saved command lines and dependencies for the $(targets) we
# may be building above, using $(if_changed{,_dep}). As an
# optimization, we don't need to read them if the target does not
# exist, we will rebuild anyway in that case.

existing-targets := $(wildcard $(sort $(targets)))

-include $(foreach f,$(existing-targets),$(dir $(f)).$(notdir $(f)).cmd)

# Create directories for object files if they do not exist
obj-dirs := $(sort $(patsubst %/,%, $(dir $(targets))))
# If targets exist, their directories apparently exist. Skip mkdir.
existing-dirs := $(sort $(patsubst %/,%, $(dir $(existing-targets))))
obj-dirs := $(strip $(filter-out $(existing-dirs), $(obj-dirs)))
ifneq ($(obj-dirs),)
$(shell mkdir -p $(obj-dirs))
endif

# Declare the contents of the PHONY variable as phony.  We keep that
# information in a variable so we can use it in if_changed and friends.
.PHONY: $(PHONY)
