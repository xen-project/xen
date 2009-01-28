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
$(call cc-option-add,CFLAGS,CC,-nopie)
$(call cc-option-add,CFLAGS,CC,-fno-stack-protector)
$(call cc-option-add,CFLAGS,CC,-fno-stack-protector-all)

# Extra CFLAGS suitable for an embedded type of environment.
CFLAGS += -fno-builtin -msoft-float
