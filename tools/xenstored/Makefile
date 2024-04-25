XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

include Makefile.common

xenstored: LDLIBS += $(LDLIBS_libxenevtchn)
xenstored: LDLIBS += $(LDLIBS_libxengnttab)
xenstored: LDLIBS += $(LDLIBS_libxenctrl)
xenstored: LDLIBS += -lrt
xenstored: LDLIBS += $(SOCKET_LIBS)

TARGETS := xenstored

.PHONY: all
all: $(TARGETS)

xenstored: $(XENSTORED_OBJS-y)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@ $(APPEND_LDFLAGS)

.PHONY: clean
clean::
	$(RM) $(TARGETS) $(DEPS_RM)

.PHONY: distclean
distclean: clean

.PHONY: TAGS
TAGS:
	etags `find . -name '*.[ch]'`

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) xenstored $(DESTDIR)$(sbindir)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(sbindir)/xenstored
	if [ -d $(DESTDIR)$(includedir)/xenstore-compat ]; then \
		rmdir --ignore-fail-on-non-empty $(DESTDIR)$(includedir)/xenstore-compat; \
	fi

-include $(DEPS_INCLUDE)
