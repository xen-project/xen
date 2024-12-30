########################################
# x86-specific definitions

export XEN_IMG_OFFSET := 0x200000

CFLAGS += -DXEN_IMG_OFFSET=$(XEN_IMG_OFFSET)

# Prevent floating-point variables from creeping into Xen.
CFLAGS += -msoft-float

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))
$(call cc-option-add,CFLAGS,CC,-Wnested-externs)
$(call as-option-add,CFLAGS,CC,"vmcall",-DHAVE_AS_VMX)
$(call as-option-add,CFLAGS,CC,"crc32 %eax$(comma)%eax",-DHAVE_AS_SSE4_2)
$(call as-option-add,CFLAGS,CC,"invept (%rax)$(comma)%rax",-DHAVE_AS_EPT)
$(call as-option-add,CFLAGS,CC,"rdrand %eax",-DHAVE_AS_RDRAND)
$(call as-option-add,CFLAGS,CC,"rdfsbase %rax",-DHAVE_AS_FSGSBASE)
$(call as-option-add,CFLAGS,CC,"xsaveopt (%rax)",-DHAVE_AS_XSAVEOPT)
$(call as-option-add,CFLAGS,CC,"rdseed %eax",-DHAVE_AS_RDSEED)
$(call as-option-add,CFLAGS,CC,"clac",-DHAVE_AS_CLAC_STAC)
$(call as-option-add,CFLAGS,CC,"clwb (%rax)",-DHAVE_AS_CLWB)
$(call as-option-add,CFLAGS,CC,".equ \"x\"$(comma)1",-DHAVE_AS_QUOTED_SYM)
$(call as-option-add,CFLAGS,CC,"invpcid (%rax)$(comma)%rax",-DHAVE_AS_INVPCID)
$(call as-option-add,CFLAGS,CC,"movdiri %rax$(comma)(%rax)",-DHAVE_AS_MOVDIR)
$(call as-option-add,CFLAGS,CC,"enqcmd (%rax)$(comma)%rax",-DHAVE_AS_ENQCMD)

# Check to see whether the assmbler supports the .nop directive.
$(call as-option-add,CFLAGS,CC,\
    ".L1: .L2: .nops (.L2 - .L1)$(comma)9",-DHAVE_AS_NOPS_DIRECTIVE)

CFLAGS += -mno-red-zone -fpic

# Xen doesn't use MMX or SSE interally.  If the compiler supports it, also skip
# the SSE setup for variadic function calls.
CFLAGS += -mno-mmx -mno-sse $(call cc-option,$(CC),-mskip-rax-setup)

ifeq ($(CONFIG_INDIRECT_THUNK),y)
# Compile with gcc thunk-extern, indirect-branch-register if available.
CFLAGS-$(CONFIG_CC_IS_GCC) += -mindirect-branch=thunk-extern
CFLAGS-$(CONFIG_CC_IS_GCC) += -mindirect-branch-register
CFLAGS-$(CONFIG_CC_IS_GCC) += -fno-jump-tables

# Enable clang retpoline support if available.
CFLAGS-$(CONFIG_CC_IS_CLANG) += -mretpoline-external-thunk
endif

# Disable the addition of a .note.gnu.property section to object files when
# livepatch support is enabled.  The contents of that section can change
# depending on the instructions used, and livepatch-build-tools doesn't know
# how to deal with such changes.
$(call cc-option-add,CFLAGS-$(CONFIG_LIVEPATCH),CC,-Wa$$(comma)-mx86-used-note=no)

ifdef CONFIG_XEN_IBT
# Force -fno-jump-tables to work around
#   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=104816
#   https://github.com/llvm/llvm-project/issues/54247
CFLAGS += -fcf-protection=branch -mmanual-endbr -fno-jump-tables
$(call cc-option-add,CFLAGS,CC,-fcf-check-attribute=no)
else
$(call cc-option-add,CFLAGS,CC,-fcf-protection=none)
endif

# If supported by the compiler, reduce stack alignment to 8 bytes. But allow
# this to be overridden elsewhere.
$(call cc-option-add,CFLAGS_stack_boundary,CC,-mpreferred-stack-boundary=3)
export CFLAGS_stack_boundary

ifeq ($(CONFIG_UBSAN),y)
# Don't enable alignment sanitisation.  x86 has efficient unaligned accesses,
# and various things (ACPI tables, hypercall pages, stubs, etc) are wont-fix.
# It also causes an as-yet-unidentified crash on native boot before the
# console starts.
$(call cc-option-add,CFLAGS_UBSAN,CC,-fno-sanitize=alignment)
endif

ifeq ($(CONFIG_LD_IS_GNU),y)
# While not much better than going by raw GNU ld version, utilize that the
# feature we're after has appeared in the same release as the
# --print-output-format command line option.
AFLAGS-$(call ld-option,--print-output-format) += -DHAVE_LD_SORT_BY_INIT_PRIORITY
else
# Assume all versions of LLD support this.
AFLAGS += -DHAVE_LD_SORT_BY_INIT_PRIORITY
endif

ifneq ($(CONFIG_PV_SHIM_EXCLUSIVE),y)

efi-check := arch/x86/efi/check

# Create the directory for out-of-tree build
$(shell mkdir -p $(dir $(efi-check)))

# Check if the compiler supports the MS ABI.
XEN_BUILD_EFI := $(call if-success,$(CC) $(filter-out -include %/include/xen/config.h,$(CFLAGS)) \
                                         -c $(srctree)/$(efi-check).c -o $(efi-check).o,y)

# Check if the linker supports PE.
EFI_LDFLAGS := $(patsubst -m%,-mi386pep,$(LDFLAGS)) --subsystem=10 --enable-long-section-names
LD_PE_check_cmd = $(call ld-option,$(EFI_LDFLAGS) --image-base=0x100000000 -o $(efi-check).efi $(efi-check).o)
XEN_BUILD_PE := $(LD_PE_check_cmd)

# If the above failed, it may be merely because of the linker not dealing well
# with debug info. Try again with stripping it.
ifeq ($(CONFIG_DEBUG_INFO)-$(XEN_BUILD_PE),y-n)
EFI_LDFLAGS += --strip-debug
XEN_BUILD_PE := $(LD_PE_check_cmd)
endif

ifeq ($(XEN_BUILD_PE),y)

# Check if the linker produces fixups in PE by default
efi-nr-fixups := $(shell LC_ALL=C $(OBJDUMP) -p $(efi-check).efi | grep '^[[:blank:]]*reloc[[:blank:]]*[0-9][[:blank:]].*DIR64$$' | wc -l)

ifeq ($(efi-nr-fixups),2)
MKRELOC := :
else
MKRELOC := arch/x86/efi/mkreloc
# If the linker produced fixups but not precisely two of them, we need to
# disable it doing so.  But if it didn't produce any fixups, it also wouldn't
# recognize the option.
ifneq ($(efi-nr-fixups),0)
EFI_LDFLAGS += --disable-reloc-section
endif
endif

endif # $(XEN_BUILD_PE)

export XEN_BUILD_EFI XEN_BUILD_PE
export EFI_LDFLAGS
endif

# Set up the assembler include path properly for older toolchains.
CFLAGS += -Wa,-I$(objtree)/include -Wa,-I$(srctree)/include
