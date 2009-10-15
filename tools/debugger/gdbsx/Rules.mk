include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -Werror -Wmissing-prototypes 
# (gcc 4.3x and later)   -Wconversion -Wno-sign-conversion

# just in case have to debug gdbsx, keep life simple.
TMPFLAGS := $(CFLAGS)
CFLAGS := $(filter-out -O% -DNDEBUG -fomit-frame-pointer, $(TMPFLAGS))
CFLAGS += -O0
