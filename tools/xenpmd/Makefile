XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror
CFLAGS += $(CFLAGS_libxenstore)

LDLIBS += $(LDLIBS_libxenstore)

.PHONY: all
all: xenpmd

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) xenpmd $(DESTDIR)$(sbindir)

.PHONY: clean
clean:
	$(RM) -f xenpmd xenpmd.o $(DEPS_RM)

.PHONY: distclean
distclean: clean

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(sbindir)/xenpmd

xenpmd: xenpmd.o Makefile
	$(CC) $(LDFLAGS) $< -o $@ $(LDLIBS) $(APPEND_LDFLAGS)

-include $(DEPS_INCLUDE)
