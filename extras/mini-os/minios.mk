#
# The file contains the common make rules for building mini-os.
#

debug = y

# Define some default flags.
# NB. '-Wcast-qual' is nasty, so I omitted it.
DEF_CFLAGS := -fno-builtin -Wall -Werror -Wredundant-decls -Wno-format
DEF_CFLAGS += -Wstrict-prototypes -Wnested-externs -Wpointer-arith -Winline
DEF_CFLAGS += -D__XEN_INTERFACE_VERSION__=$(XEN_INTERFACE_VERSION)

DEF_ASFLAGS = -D__ASSEMBLY__

ifeq ($(debug),y)
DEF_CFLAGS += -g
else
DEF_CFLAGS += -O3
endif

# Build the CFLAGS and ASFLAGS for compiling and assembling.
# DEF_... flags are the common mini-os flags,
# ARCH_... flags may be defined in arch/$(TARGET_ARCH_FAM/rules.mk
CFLAGS := $(DEF_CFLAGS) $(ARCH_CFLAGS)
ASFLAGS := $(DEF_ASFLAGS) $(ARCH_ASFLAGS)

# The path pointing to the architecture specific header files.
ARCH_SPEC_INC := $(MINI-OS_ROOT)/include/$(TARGET_ARCH_FAM)

# Find all header files for checking dependencies.
HDRS := $(wildcard $(MINI-OS_ROOT)/include/*.h)
HDRS += $(wildcard $(MINI-OS_ROOT)/include/xen/*.h)
HDRS += $(wildcard $(ARCH_SPEC_INC)/*.h)
# For special wanted header directories.
extra_heads := $(foreach dir,$(EXTRA_INC),$(wildcard $(dir)/*.h))
HDRS += $(extra_heads)

# Add the special header directories to the include paths.
extra_incl := $(foreach dir,$(EXTRA_INC),-I$(MINI-OS_ROOT)/include/$(dir))
override CPPFLAGS := -I$(MINI-OS_ROOT)/include $(CPPFLAGS) -I$(ARCH_SPEC_INC)	$(extra_incl)

# The name of the architecture specific library.
# This is on x86_32: libx86_32.a
# $(ARCH_LIB) has to built in the architecture specific directory.
ARCH_LIB_NAME = $(TARGET_ARCH)
ARCH_LIB := lib$(ARCH_LIB_NAME).a

# This object contains the entrypoint for startup from Xen.
# $(HEAD_ARCH_OBJ) has to be built in the architecture specific directory.
HEAD_ARCH_OBJ := $(TARGET_ARCH).o
HEAD_OBJ := $(TARGET_ARCH_DIR)/$(HEAD_ARCH_OBJ)


%.o: %.c $(HDRS) Makefile $(SPEC_DEPENDS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

%.o: %.S $(HDRS) Makefile $(SPEC_DEPENDS)
	$(CC) $(ASFLAGS) $(CPPFLAGS) -c $< -o $@




