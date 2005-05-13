# -*- mode: Makefile; -*-
#============================================================================
#
# Mike Wray <mike.wray@hp.com>
#============================================================================

INSTALL		= install
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

XEN_ROOT  = ../..
include $(XEN_ROOT)/tools/Rules.mk

XFRD_INSTALL_DIR = /usr/sbin

vpath %.h      $(XEN_LIBXC)
INCLUDES += -I $(XEN_LIBXC)

vpath %c       $(XEN_LIBXUTIL)
INCLUDES += -I $(XEN_LIBXUTIL)

include Make.xfrd

UTIL_LIB_OBJ = $(UTIL_LIB_SRC:.c=.o)

XFRD_PROG_OBJ = $(XFRD_PROG_SRC:.c=.o)
XFRD_PROG_OBJ += $(UTIL_LIB)

CC := gcc

CFLAGS += -Wall -Werror -O3 -fno-strict-aliasing
CFLAGS += $(INCLUDES)

# Make gcc generate dependencies.
CFLAGS += -Wp,-MD,.$(@F).d
PROG_DEP = .*.d

#$(warning XFRD_PROG_OBJ= $(XFRD_PROG_OBJ))
#$(warning UTIL_LIB= $(UTIL_LIB))
#$(warning UTIL_LIB_OBJ= $(UTIL_LIB_OBJ))

# Libraries for xfrd.
XFRD_LIBS :=

XFRD_LIBS += -L $(XEN_LIBXC) -lxc
XFRD_LIBS += -L $(XEN_LIBXUTIL) -lxutil

# zlib library.
XFRD_LIBS += -lz

#$(warning XFRD_LIBS = $(XFRD_LIBS))

all: build
build: xfrd

xfrd: $(XFRD_PROG_OBJ)
	$(CC) -o $@ $^ $(XFRD_LIBS)

.PHONY: install
install: xfrd
	[ -d $(DESTDIR)$(XFRD_INSTALL_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XFRD_INSTALL_DIR)
	$(INSTALL_PROG) xfrd $(DESTDIR)$(XFRD_INSTALL_DIR)

.PHONY: libutil
libutil: $(UTIL_LIB)

$(UTIL_LIB): $(UTIL_LIB_OBJ)
	$(AR) rc $@ $^

.PHONY: clean
clean:
	$(RM) *.o *.a *.so *~ xfrd
	$(RM) $(PROG_DEP)

$(XFRD_PROG_OBJ): Makefile
-include $(PROG_DEP)

