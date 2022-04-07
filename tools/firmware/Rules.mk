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

$(call cc-option-add,CFLAGS,CC,-fcf-protection=none)

# Do not add the .note.gnu.property section to any of the firmware objects: it
# breaks the rombios binary and is not useful for firmware anyway.
$(call cc-option-add,CFLAGS,CC,-Wa$$(comma)-mx86-used-note=no)

# Extra CFLAGS suitable for an embedded type of environment.
CFLAGS += -fno-builtin -msoft-float
