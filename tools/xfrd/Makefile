# -*- mode: Makefile; -*-
#============================================================================
#
# Mike Wray <mike.wray@hp.com>
#============================================================================

XEN_ROOT  = ../..
include $(XEN_ROOT)/tools/Make.defs

XFRD_INSTALL_DIR = /usr/sbin

vpath %.h      $(XEN_HYPERVISOR_IFS)
INCLUDES += -I $(XEN_HYPERVISOR_IFS)

vpath %h       $(XEN_LINUX_INCLUDE)
INCLUDES += -I $(XEN_LINUX_INCLUDE)

vpath %.h      $(XEN_XU)
INCLUDES += -I $(XEN_XU)

vpath %c       $(XEN_LIBXUTIL)
INCLUDES += -I $(XEN_LIBXUTIL)

include Make.xfrd

UTIL_LIB_OBJ = $(UTIL_LIB_SRC:.c=.o)

XFRD_PROG_OBJ = $(XFRD_PROG_SRC:.c=.o)
XFRD_PROG_OBJ += $(UTIL_LIB)

CPPFLAGS += -D _XEN_XFR_STUB_

CFLAGS += -g
CFLAGS += -Wall
CFALGS += -Werror
CFLAGS += $(INCLUDES)
# Make gcc generate dependencies.
CFLAGS += -Wp,-MD,.$(@F).d
PROG_DEP = .*.d

#LDFLAGS += -L $(COMPRESS_DIR) -lz

$(warning XFRD_PROG_OBJ= $(XFRD_PROG_OBJ))
$(warning UTIL_LIB= $(UTIL_LIB))
$(warning UTIL_LIB_OBJ= $(UTIL_LIB_OBJ))

all: xfrd

xfrd: $(XFRD_PROG_OBJ) -lz

.PHONY: install
install: xfrd
	mkdir -p $(prefix)/$(XFRD_INSTALL_DIR)
	install -m 0755 xfrd $(prefix)/$(XFRD_INSTALL_DIR)

.PHONY: libutil
libutil: $(UTIL_LIB)

$(UTIL_LIB): $(UTIL_LIB_OBJ)
	$(AR) rc $@ $^

.PHONY: clean
clean:
	$(RM) *.o *.a *.so *~ xfrd
	$(RM) $(PROG_DEP)

-include $(PROG_DEP)

