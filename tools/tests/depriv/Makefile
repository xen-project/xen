XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror -Wno-declaration-after-statement

CFLAGS += $(CFLAGS_xeninclude)
CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_libxencall)
CFLAGS += $(CFLAGS_libxenevtchn)
CFLAGS += $(CFLAGS_libxengnttab)
CFLAGS += $(CFLAGS_libxenforeignmemory)
CFLAGS += $(CFLAGS_libxendevicemodel)
CFLAGS += $(CFLAGS_libxentoolcore)
CFLAGS += $(CFLAGS_libxentoollog)

LDLIBS += $(LDLIBS_xeninclude)
LDLIBS += $(LDLIBS_libxenctrl)
LDLIBS += $(LDLIBS_libxencall)
LDLIBS += $(LDLIBS_libxenevtchn)
LDLIBS += $(LDLIBS_libxengnttab)
LDLIBS += $(LDLIBS_libxenforeignmemory)
LDLIBS += $(LDLIBS_libxendevicemodel)
LDLIBS += $(LDLIBS_libxentoolcore)
LDLIBS += $(LDLIBS_libxentoollog)

TARGETS-y := depriv-fd-checker
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

install uninstall:

-include $(DEPS_INCLUDE)
