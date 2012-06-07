# Firmware is a 32-bit target
override XEN_TARGET_ARCH = x86_32

# User-supplied CFLAGS are not useful here.
CFLAGS =
EXTRA_CFLAGS_XEN_TOOLS =

include $(XEN_ROOT)/tools/Rules.mk

ifneq ($(debug),y)
CFLAGS += -DNDEBUG
endif

CFLAGS += -Werror

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))

# Extra CFLAGS suitable for an embedded type of environment.
CFLAGS += -fno-builtin -msoft-float
