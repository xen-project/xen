#
# tools/9pfsd/Makefile
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += $(PTHREAD_CFLAGS) -D_GNU_SOURCE
LDFLAGS += $(PTHREAD_LDFLAGS)

TARGETS := xen-9pfsd

XEN-9PFSD_OBJS = xen-9pfsd.o io.o
$(XEN-9PFSD_OBJS): CFLAGS += $(CFLAGS_libxenstore)
$(XEN-9PFSD_OBJS): CFLAGS += $(CFLAGS_libxenevtchn)
$(XEN-9PFSD_OBJS): CFLAGS += $(CFLAGS_libxengnttab)
xen-9pfsd: LDLIBS += $(call xenlibs-ldlibs,store evtchn gnttab)

.PHONY: all
all: $(TARGETS)

xen-9pfsd: $(XEN-9PFSD_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(XEN-9PFSD_OBJS) $(LDLIBS) $(APPEND_LDFLAGS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	for i in $(TARGETS); do $(INSTALL_PROG) $$i $(DESTDIR)$(LIBEXEC_BIN); done

.PHONY: uninstall
uninstall:
	for i in $(TARGETS); do rm -f $(DESTDIR)$(LIBEXEC_BIN)/$$i; done

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) $(DEPS_RM)

distclean: clean
