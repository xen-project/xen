# Firmware is a 32-bit target
override XEN_TARGET_ARCH = x86_32

# User-supplied CFLAGS are not useful here.
CFLAGS =
EXTRA_CFLAGS_XEN_TOOLS =

include $(XEN_ROOT)/tools/Rules.mk

ifneq ($(debug),y)
CFLAGS += -DNDEBUG
endif

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))

$(call cc-option-add,CFLAGS,CC,-fcf-protection=none)

# Do not add the .note.gnu.property section to any of the firmware objects: it
# breaks the rombios binary and is not useful for firmware anyway.
$(call cc-option-add,CFLAGS,CC,-Wa$$(comma)-mx86-used-note=no)

# Extra CFLAGS suitable for an embedded type of environment.
CFLAGS += -ffreestanding -msoft-float

# Use our own set of stand alone headers to build firmware.
#
# Ideally using -ffreestanding should be enough, but that relies on the
# compiler having the right order for include paths (ie: compiler private
# headers before system ones) or the libc headers having proper arch-agnostic
# freestanding support. This is not the case in Alpine at least which searches
# system headers before compiler ones and has arch-specific libc headers. This
# has been reported upstream:
# https://gitlab.alpinelinux.org/alpine/aports/-/issues/12477
# In the meantime (and for resilience against broken systems) use our own set
# of headers that provide what's needed for the firmware build.
CFLAGS += -nostdinc -I$(XEN_ROOT)/tools/firmware/include
