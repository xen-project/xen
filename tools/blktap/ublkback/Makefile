
XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

INCLUDES += -I..

INSTALL            = install
INSTALL_PROG = $(INSTALL) -m0755
IBIN         = ublkback
INSTALL_DIR  = /usr/sbin

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -fno-strict-aliasing
CFLAGS   += -I $(XEN_LIBXC)
CFLAGS   += $(INCLUDES) -I.
CFLAGS   += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

OBJS     = $(patsubst %.c,%.o,$(SRCS))

all: $(IBIN)

LINUX_ROOT := $(wildcard $(XEN_ROOT)/linux-2.6.*-xen-sparse)

install:
	$(INSTALL_PROG) $(IBIN) $(DESTDIR)$(INSTALL_DIR)
clean:
	rm -rf *.o*~ $(DEPS) xen TAGS $(IBIN)

ublkback: 
	$(CC) $(CFLAGS) -o ublkback -L$(XEN_LIBXC) -L. -L..  \
	      -lblktap -laio ublkback.c ublkbacklib.c -pg

.PHONY: clean install

-include $(DEPS)
