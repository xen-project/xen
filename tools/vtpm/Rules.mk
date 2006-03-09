# Base definitions and rules (XEN_ROOT must be defined in including Makefile)
include $(XEN_ROOT)/tools/Rules.mk

#
# Tool definitions
#

# Installation program and options
INSTALL         = install
INSTALL_PROG    = $(INSTALL) -m0755
INSTALL_DIR     = $(INSTALL) -d -m0755

# Xen tools installation directory
TOOLS_INSTALL_DIR = $(DESTDIR)/usr/bin

# General compiler flags
CFLAGS   = -Werror -g3 -I.

# For generating dependencies
CFLAGS	+= -Wp,-MD,.$(@F).d

DEP_FILES	= .*.d

# Generic project files
HDRS	= $(wildcard *.h)
SRCS	= $(wildcard *.c)
OBJS	= $(patsubst %.c,%.o,$(SRCS))

# Generic (non-header) dependencies
$(SRCS): Makefile $(XEN_ROOT)/tools/Rules.mk $(XEN_ROOT)/tools/vtpm/Rules.mk

$(OBJS): $(SRCS)

-include $(DEP_FILES)

BUILD_EMULATOR = n

# Make sure these are just rules
.PHONY : all build install clean
