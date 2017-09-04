XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror
CFLAGS += -DXC_WANT_COMPAT_DEVICEMODEL_API

CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_libxenguest)
CFLAGS += $(CFLAGS_libxenevtchn)
CFLAGS += $(CFLAGS_xeninclude)

TARGETS-y := xen-access
TARGETS := $(TARGETS-y)

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS)

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) *~ $(DEPS_RM)

.PHONY: distclean
distclean: clean

xen-access: xen-access.o Makefile
	$(CC) -o $@ $< $(LDFLAGS) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenevtchn)

-include $(DEPS_INCLUDE)
