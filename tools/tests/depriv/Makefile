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

INSTALL_PRIVBIN-y += depriv-fd-checker
INSTALL_PRIVBIN := $(INSTALL_PRIVBIN-y)
TARGETS += $(INSTALL_PRIVBIN)

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS)

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) *~ $(DEPS_RM)

.PHONY: distclean
distclean: clean

depriv-fd-checker: depriv-fd-checker.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS) $(APPEND_LDFLAGS)

install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) $(INSTALL_PRIVBIN) $(DESTDIR)$(LIBEXEC_BIN)

.PHONY: uninstall
uninstall:
	rm -f $(addprefix $(DESTDIR)$(LIBEXEC_BIN)/, $(INSTALL_PRIVBIN))

-include $(DEPS_INCLUDE)
