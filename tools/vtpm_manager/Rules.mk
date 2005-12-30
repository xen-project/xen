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
CFLAGS	= -Wall -Werror -g3 -I.

# For generating dependencies
CFLAGS	+= -Wp,-MD,.$(@F).d

DEP_FILES	= .*.d

# Generic project files
HDRS	= $(wildcard *.h)
SRCS	= $(wildcard *.c)
OBJS	= $(patsubst %.c,%.o,$(SRCS))

# Generic (non-header) dependencies
$(SRCS): Makefile $(XEN_ROOT)/tools/Rules.mk $(XEN_ROOT)/tools/vtpm_manager/Rules.mk

$(OBJS): $(SRCS)

-include $(DEP_FILES)

# Make sure these are just rules
.PHONY : all build install clean

#
# Project-specific definitions
#

# Logging Level. See utils/tools.h for usage
CFLAGS += -DLOGGING_MODULES="(BITMASK(VTPM_LOG_TCS)|BITMASK(VTPM_LOG_VTSP)|BITMASK(VTPM_LOG_VTPM)|BITMASK(VTPM_LOG_VTPM_DEEP))"

# Silent Mode
#CFLAGS += -DLOGGING_MODULES=0x0
#CFLAGS += -DLOGGING_MODULES=0xff

# Use frontend/backend pairs between manager & DMs?
#CFLAGS += -DVTPM_MULTI_VM

# vtpm_manager listens on /tmp/in.fifo and /tmp/out.fifo rather than backend
#CFLAGS += -DDUMMY_BACKEND

# Do not have manager launch DMs.
#CFLAGS += -DMANUAL_DM_LAUNCH

# Fixed OwnerAuth
#CFLAGS += -DWELL_KNOWN_OWNER_AUTH

# TPM Hardware Device or TPM Simulator
#CFLAGS += -DTPM_HWDEV

# Include
CFLAGS += -I$(XEN_ROOT)/tools/vtpm_manager/crypto
CFLAGS += -I$(XEN_ROOT)/tools/vtpm_manager/util
CFLAGS += -I$(XEN_ROOT)/tools/vtpm_manager/tcs
