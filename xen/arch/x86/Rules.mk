########################################
# x86-specific definitions

HAS_ACPI := y
HAS_VGA  := y
HAS_CPUFREQ := y
HAS_PCI := y
HAS_PASSTHROUGH := y
HAS_NS16550 := y
HAS_KEXEC := y
xenoprof := y

#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#
supervisor_mode_kernel ?= n

# Solaris grabs stdarg.h and friends from the system include directory.
# Clang likewise.
ifneq ($(XEN_OS),SunOS)
CFLAGS-$(gcc) += -nostdinc
endif

CFLAGS += -fno-builtin -fno-common -Wredundant-decls
CFLAGS += -iwithprefix include -Werror -Wno-pointer-arith -pipe
CFLAGS += -I$(BASEDIR)/include 
CFLAGS += -I$(BASEDIR)/include/asm-x86/mach-generic
CFLAGS += -I$(BASEDIR)/include/asm-x86/mach-default

# Prevent floating-point variables from creeping into Xen.
CFLAGS += -msoft-float

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))
$(call cc-option-add,CFLAGS,CC,-Wnested-externs)

ifeq ($(supervisor_mode_kernel),y)
CFLAGS += -DCONFIG_X86_SUPERVISOR_MODE_KERNEL=1
endif

x86 := y

ifeq ($(TARGET_SUBARCH),x86_32)
x86_32 := y
x86_64 := n
endif

ifeq ($(TARGET_SUBARCH),x86_64)
CFLAGS += -mno-red-zone -mno-sse -fpic
CFLAGS += -fno-asynchronous-unwind-tables
# -fvisibility=hidden reduces -fpic cost, if it's available
ifneq ($(call cc-option,$(CC),-fvisibility=hidden,n),n)
CFLAGS += -DGCC_HAS_VISIBILITY_ATTRIBUTE
endif
x86_32 := n
x86_64 := y
endif

# Require GCC v3.4+ (to avoid issues with alignment constraints in Xen headers)
check-$(gcc) = $(call cc-ver-check,CC,0x030400,"Xen requires at least gcc-3.4")
$(eval $(check-y))
