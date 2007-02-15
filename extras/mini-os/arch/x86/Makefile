#
# x86 architecture specific makefiles.
# It's is used for x86_32, x86_32y and x86_64
#

# include arch.mk has to be before mini-os.mk!
include arch.mk
include ../../minios.mk

# Sources here are all *.c *.S without $(TARGET_ARCH).S
# This is handled in $(HEAD_ARCH_OBJ)
ARCH_SRCS := $(wildcard *.c)

# The objects built from the sources.
ARCH_OBJS := $(patsubst %.c,%.o,$(ARCH_SRCS))

all: $(ARCH_LIB)

# $(HEAD_ARCH_OBJ) is only build here, needed on linking
# in ../../Makefile.
$(ARCH_LIB): $(ARCH_OBJS) $(HEAD_ARCH_OBJ)
	$(AR) rv $(ARCH_LIB) $(ARCH_OBJS)

clean:
	rm -f $(ARCH_LIB) $(ARCH_OBJS) $(HEAD_ARCH_OBJ)

