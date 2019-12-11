########################################
# x86-specific definitions

XEN_IMG_OFFSET := 0x200000

CFLAGS += -I$(BASEDIR)/include
CFLAGS += -I$(BASEDIR)/include/asm-x86/mach-generic
CFLAGS += -I$(BASEDIR)/include/asm-x86/mach-default
CFLAGS += -DXEN_IMG_OFFSET=$(XEN_IMG_OFFSET)
CFLAGS += '-D__OBJECT_LABEL__=$(subst /,$$,$(subst -,_,$(subst $(BASEDIR)/,,$(CURDIR))/$@))'

# Prevent floating-point variables from creeping into Xen.
CFLAGS += -msoft-float

ifeq ($(clang),y)
# Note: Any test which adds -no-integrated-as will cause subsequent tests to
# succeed, and not trigger further additions.
#
# The tests to select whether the integrated assembler is usable need to happen
# before testing any assembler features, or else the result of the tests would
# be stale if the integrated assembler is not used.

# Older clang's built-in assembler doesn't understand .skip with labels:
# https://bugs.llvm.org/show_bug.cgi?id=27369
$(call as-option-add,CFLAGS,CC,".L0: .L1: .skip (.L1 - .L0)",,\
                     -no-integrated-as)

# Check whether clang asm()-s support .include.
$(call as-option-add,CFLAGS,CC,".include \"asm/indirect_thunk_asm.h\"",,\
                     -no-integrated-as)

# Check whether clang keeps .macro-s between asm()-s:
# https://bugs.llvm.org/show_bug.cgi?id=36110
$(call as-option-add,CFLAGS,CC,\
                     ".macro FOO;.endm"$$(close); asm volatile $$(open)".macro FOO;.endm",\
                     -no-integrated-as)
endif

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))
$(call cc-option-add,CFLAGS,CC,-Wnested-externs)
$(call as-option-add,CFLAGS,CC,"vmcall",-DHAVE_AS_VMX)
$(call as-option-add,CFLAGS,CC,"crc32 %eax$$(comma)%eax",-DHAVE_AS_SSE4_2)
$(call as-option-add,CFLAGS,CC,"invept (%rax)$$(comma)%rax",-DHAVE_AS_EPT)
$(call as-option-add,CFLAGS,CC,"rdrand %eax",-DHAVE_AS_RDRAND)
$(call as-option-add,CFLAGS,CC,"rdfsbase %rax",-DHAVE_AS_FSGSBASE)
$(call as-option-add,CFLAGS,CC,"xsaveopt (%rax)",-DHAVE_AS_XSAVEOPT)
$(call as-option-add,CFLAGS,CC,"rdseed %eax",-DHAVE_AS_RDSEED)
$(call as-option-add,CFLAGS,CC,"clwb (%rax)",-DHAVE_AS_CLWB)
$(call as-option-add,CFLAGS,CC,".equ \"x\"$$(comma)1", \
                     -U__OBJECT_LABEL__ -DHAVE_AS_QUOTED_SYM \
                     '-D__OBJECT_LABEL__=$(subst $(BASEDIR)/,,$(CURDIR))/$$@')
$(call as-option-add,CFLAGS,CC,"invpcid (%rax)$$(comma)%rax",-DHAVE_AS_INVPCID)

# GAS's idea of true is -1.  Clang's idea is 1
$(call as-option-add,CFLAGS,CC,\
    ".if ((1 > 0) < 0); .error \"\";.endif",,-DHAVE_AS_NEGATIVE_TRUE)

# Check to see whether the assmbler supports the .nop directive.
$(call as-option-add,CFLAGS,CC,\
    ".L1: .L2: .nops (.L2 - .L1)$$(comma)9",-DHAVE_AS_NOPS_DIRECTIVE)

CFLAGS += -mno-red-zone -fpic -fno-asynchronous-unwind-tables

# Xen doesn't use SSE interally.  If the compiler supports it, also skip the
# SSE setup for variadic function calls.
CFLAGS += -mno-sse $(call cc-option,$(CC),-mskip-rax-setup)

# -fvisibility=hidden reduces -fpic cost, if it's available
ifneq ($(call cc-option,$(CC),-fvisibility=hidden,n),n)
CFLAGS += -DGCC_HAS_VISIBILITY_ATTRIBUTE
endif

# Compile with thunk-extern, indirect-branch-register if avaiable.
ifeq ($(CONFIG_INDIRECT_THUNK),y)
CFLAGS += -mindirect-branch=thunk-extern -mindirect-branch-register
CFLAGS += -fno-jump-tables
endif

# If supported by the compiler, reduce stack alignment to 8 bytes. But allow
# this to be overridden elsewhere.
$(call cc-option-add,CFLAGS-stack-boundary,CC,-mpreferred-stack-boundary=3)
CFLAGS += $(CFLAGS-stack-boundary)

ifeq ($(CONFIG_UBSAN),y)
# Don't enable alignment sanitisation.  x86 has efficient unaligned accesses,
# and various things (ACPI tables, hypercall pages, stubs, etc) are wont-fix.
# It also causes an as-yet-unidentified crash on native boot before the
# console starts.
$(call cc-option-add,CFLAGS_UBSAN,CC,-fno-sanitize=alignment)
endif

# Set up the assembler include path properly for older toolchains.
CFLAGS += -Wa,-I$(BASEDIR)/include

