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

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))
$(call cc-option-add,CFLAGS,CC,-Wnested-externs)
$(call as-option-add,CFLAGS,CC,"vmcall",-DHAVE_AS_VMX)
$(call as-option-add,CFLAGS,CC,"crc32 %eax$$(comma)%eax",-DHAVE_AS_SSE4_2)
$(call as-option-add,CFLAGS,CC,"invept (%rax)$$(comma)%rax",-DHAVE_AS_EPT)
$(call as-option-add,CFLAGS,CC,"rdrand %eax",-DHAVE_AS_RDRAND)
$(call as-option-add,CFLAGS,CC,"rdfsbase %rax",-DHAVE_AS_FSGSBASE)
$(call as-option-add,CFLAGS,CC,"rdseed %eax",-DHAVE_AS_RDSEED)
$(call as-option-add,CFLAGS,CC,".equ \"x\"$$(comma)1", \
                     -U__OBJECT_LABEL__ -DHAVE_AS_QUOTED_SYM \
                     '-D__OBJECT_LABEL__=$(subst $(BASEDIR)/,,$(CURDIR))/$$@')
$(call as-option-add,CFLAGS,CC,"invpcid (%rax)$$(comma)%rax",-DHAVE_AS_INVPCID)

# GAS's idea of true is -1.  Clang's idea is 1
$(call as-option-add,CFLAGS,CC,\
    ".if ((1 > 0) < 0); .error \"\";.endif",,-DHAVE_AS_NEGATIVE_TRUE)

CFLAGS += -mno-red-zone -fpic -fno-asynchronous-unwind-tables

# Xen doesn't use SSE interally.  If the compiler supports it, also skip the
# SSE setup for variadic function calls.
CFLAGS += -mno-sse $(call cc-option,$(CC),-mskip-rax-setup)

# -fvisibility=hidden reduces -fpic cost, if it's available
ifneq ($(call cc-option,$(CC),-fvisibility=hidden,n),n)
CFLAGS += -DGCC_HAS_VISIBILITY_ATTRIBUTE
endif

# Compile with thunk-extern, indirect-branch-register if avaiable.
ifneq ($(call cc-option,$(CC),-mindirect-branch-register,n),n)
CFLAGS += -mindirect-branch=thunk-extern -mindirect-branch-register
CFLAGS += -DCONFIG_INDIRECT_THUNK
export CONFIG_INDIRECT_THUNK=y
endif

# Set up the assembler include path properly for older toolchains.
CFLAGS += -Wa,-I$(BASEDIR)/include

ifeq ($(clang),y)
# Note: Any test which adds -no-integrated-as will cause subsequent tests to
# succeed, and not trigger further additions.

# Check whether clang asm()-s support .include.
$(call as-option-add,CFLAGS,CC,".include \"asm/indirect_thunk_asm.h\"",,\
                     -no-integrated-as)

# Check whether clang keeps .macro-s between asm()-s:
# https://bugs.llvm.org/show_bug.cgi?id=36110
$(call as-option-add,CFLAGS,CC,\
                     ".macro FOO\n.endm\"); asm volatile (\".macro FOO\n.endm",\
                     -no-integrated-as)
endif
