XEN_ROOT=../../../
BLKTAP_ROOT := ..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y    :=
SUBDIRS-y    += lib

IBIN          = blktapctrl
INST_DIR      = $(SBINDIR)

LIBS         := -lxenstore
LIBS         += -Llib
LIBS         += -lblktap
LIBS         += -lxenctrl

ifneq ($(USE_SYSTEM_LIBRARIES),y)
INCLUDES     += -I $(XEN_LIBXC) -I $(XEN_XENSTORE)
LIBS         += -L $(XEN_LIBXC) -L $(XEN_XENSTORE)
endif

OBJS         := tapdisk-dispatch-common.o
OBJS         += tapdisk-channel.o

CFLAGS       += -Werror
CFLAGS       += -Wno-unused
CFLAGS       += -fno-strict-aliasing -fPIC
CFLAGS       += -Ilib -I../include -I../drivers -I../../include $(INCLUDES)
CFLAGS       += -D_GNU_SOURCE
CFLAGS       += -g

# Get gcc to generate the dependencies for us.
CFLAGS       += -Wp,-MD,.$(@F).d
DEPS          = .*.d

all: $(IBIN)

blktapctrl: tapdisk-daemon.c $(OBJS) subdir-all-lib
	$(CC) $(CFLAGS) -o blktapctrl tapdisk-daemon.c $(LDFLAGS) $(LIBS) $(OBJS)

install: all
	$(INSTALL_DIR) -p $(DESTDIR)$(INST_DIR)
	$(INSTALL_PROG) $(IBIN) $(DESTDIR)$(INST_DIR)

clean:
	rm -rf *.o *~ $(IBIN) $(DEPS) xen TAGS

.PHONY: all clean install blktapctrl
all clean install: %: subdirs-%

-include $(DEPS)

