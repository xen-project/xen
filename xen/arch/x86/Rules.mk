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
$(call as-insn-check,CFLAGS,CC,"vmcall",-DHAVE_GAS_VMX)
$(call as-insn-check,CFLAGS,CC,"crc32 %eax$$(comma)%eax",-DHAVE_GAS_SSE4_2)
$(call as-insn-check,CFLAGS,CC,"invept (%rax)$$(comma)%rax",-DHAVE_GAS_EPT)
$(call as-insn-check,CFLAGS,CC,"rdrand %eax",-DHAVE_GAS_RDRAND)
$(call as-insn-check,CFLAGS,CC,"rdfsbase %rax",-DHAVE_GAS_FSGSBASE)
$(call as-insn-check,CFLAGS,CC,"rdseed %eax",-DHAVE_GAS_RDSEED)
$(call as-insn-check,CFLAGS,CC,".equ \"x\"$$(comma)1", \
                     -U__OBJECT_LABEL__ -DHAVE_GAS_QUOTED_SYM \
                     '-D__OBJECT_LABEL__=$(subst $(BASEDIR)/,,$(CURDIR))/$$@')

CFLAGS += -mno-red-zone -mno-sse -fpic
CFLAGS += -fno-asynchronous-unwind-tables
# -fvisibility=hidden reduces -fpic cost, if it's available
ifneq ($(call cc-option,$(CC),-fvisibility=hidden,n),n)
CFLAGS += -DGCC_HAS_VISIBILITY_ATTRIBUTE
endif
