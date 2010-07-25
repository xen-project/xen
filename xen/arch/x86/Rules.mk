########################################
# x86-specific definitions

HAS_ACPI := y
HAS_VGA  := y
xenoprof := y

#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#
supervisor_mode_kernel ?= n

# Solaris grabs stdarg.h and friends from the system include directory.
ifneq ($(XEN_OS),SunOS)
CFLAGS += -nostdinc
endif

CFLAGS += -fno-builtin -fno-common
CFLAGS += -iwithprefix include -Werror -Wno-pointer-arith -pipe
CFLAGS += -I$(BASEDIR)/include 
CFLAGS += -I$(BASEDIR)/include/asm-x86/mach-generic
CFLAGS += -I$(BASEDIR)/include/asm-x86/mach-default

# Prevent floating-point variables from creeping into Xen.
CFLAGS += -msoft-float

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))

ifeq ($(supervisor_mode_kernel),y)
CFLAGS += -DCONFIG_X86_SUPERVISOR_MODE_KERNEL=1
endif

x86 := y

ifeq ($(TARGET_SUBARCH),x86_32)
x86_32 := y
x86_64 := n
endif

ifeq ($(TARGET_SUBARCH),x86_64)
CFLAGS += -mno-red-zone -fpic
CFLAGS += -fno-asynchronous-unwind-tables
# -fvisibility=hidden reduces -fpic cost, if it's available
ifneq ($(call cc-option,$(CC),-fvisibility=hidden,n),n)
CFLAGS += -DGCC_HAS_VISIBILITY_ATTRIBUTE
endif
x86_32 := n
x86_64 := y
endif

# Require GCC v3.4+ (to avoid issues with alignment constraints in Xen headers)
$(call cc-ver-check,CC,0x030400,"Xen requires at least gcc-3.4")
