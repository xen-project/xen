# Firmware is a 32-bit target
override XEN_TARGET_ARCH = x86_32

# User-supplied CFLAGS are not useful here.
CFLAGS =

include $(XEN_ROOT)/tools/Rules.mk

ifneq ($(debug),y)
CFLAGS += -DNDEBUG
endif

CFLAGS += -Werror

# Disable PIE/SSP if GCC supports them. They can break us.
CFLAGS += $(call cc-option,$(CC),-nopie,)
CFLAGS += $(call cc-option,$(CC),-fno-stack-protector,)
CFLAGS += $(call cc-option,$(CC),-fno-stack-protector-all,)

# Extra CFLAGS suitable for an embedded type of environment.
CFLAGS += -fno-builtin -msoft-float
