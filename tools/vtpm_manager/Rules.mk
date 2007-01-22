# Base definitions and rules (XEN_ROOT must be defined in including Makefile)
include $(XEN_ROOT)/tools/Rules.mk

#
# Tool definitions
#

# Xen tools installation directory
TOOLS_INSTALL_DIR = $(DESTDIR)/usr/bin

# General compiler flags
CFLAGS	= -Werror -g3 -I.

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

# Need UNIX98 spec for pthread rwlocks
CFLAGS += -D_GNU_SOURCE

# Logging Level. See utils/tools.h for usage
CFLAGS += -DLOGGING_MODULES="(BITMASK(VTPM_LOG_TCS)|BITMASK(VTPM_LOG_VTSP)|BITMASK(VTPM_LOG_VTPM))"

# Silent Mode
#CFLAGS += -DLOGGING_MODULES=0x0
#CFLAGS += -DLOGGING_MODULES=0xff

# Use frontend/backend pairs between manager & DMs?
#CFLAGS += -DVTPM_MULTI_VM

# vtpm_manager listens on fifo's rather than backend
#CFLAGS += -DDUMMY_BACKEND

# TCS talks to fifo's rather than /dev/tpm. TPM Emulator assumed on fifos
#CFLAGS += -DDUMMY_TPM

# Do not have manager launch DMs.
#CFLAGS += -DMANUAL_DM_LAUNCH

# Fixed OwnerAuth
#CFLAGS += -DWELL_KNOWN_OWNER_AUTH

# Include
CFLAGS += -I$(XEN_ROOT)/tools/vtpm_manager/crypto
CFLAGS += -I$(XEN_ROOT)/tools/vtpm_manager/util
CFLAGS += -I$(XEN_ROOT)/tools/vtpm_manager/tcs
CFLAGS += -I$(XEN_ROOT)/tools/vtpm_manager/manager
