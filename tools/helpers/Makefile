#
# tools/helpers/Makefile
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

TARGETS := xen-init-dom0
ifeq ($(CONFIG_Linux),y)
ifeq ($(CONFIG_X86),y)
TARGETS += init-xenstore-domain
endif
ifeq ($(CONFIG_ARM),y)
TARGETS += init-dom0less
endif
endif

XEN_INIT_DOM0_OBJS = xen-init-dom0.o init-dom-json.o
$(XEN_INIT_DOM0_OBJS): CFLAGS += $(CFLAGS_libxentoollog)
$(XEN_INIT_DOM0_OBJS): CFLAGS += $(CFLAGS_libxenstore)
$(XEN_INIT_DOM0_OBJS): CFLAGS += $(CFLAGS_libxenlight)
$(XEN_INIT_DOM0_OBJS): CFLAGS += $(CFLAGS_libxenctrl)
xen-init-dom0: LDLIBS += $(call xenlibs-ldlibs,ctrl toollog store light)

INIT_XENSTORE_DOMAIN_OBJS = init-xenstore-domain.o init-dom-json.o
$(INIT_XENSTORE_DOMAIN_OBJS): CFLAGS += $(CFLAGS_libxentoollog)
$(INIT_XENSTORE_DOMAIN_OBJS): CFLAGS += $(CFLAGS_libxenguest)
$(INIT_XENSTORE_DOMAIN_OBJS): CFLAGS += $(CFLAGS_libxenctrl)
$(INIT_XENSTORE_DOMAIN_OBJS): CFLAGS += $(CFLAGS_libxenstore)
$(INIT_XENSTORE_DOMAIN_OBJS): CFLAGS += $(CFLAGS_libxenlight)
$(INIT_XENSTORE_DOMAIN_OBJS): CFLAGS += -include $(XEN_ROOT)/tools/config.h
init-xenstore-domain: LDLIBS += $(call xenlibs-ldlibs,toollog store ctrl guest light)

INIT_DOM0LESS_OBJS = init-dom0less.o init-dom-json.o
$(INIT_DOM0LESS_OBJS): CFLAGS += $(CFLAGS_libxentoollog)
$(INIT_DOM0LESS_OBJS): CFLAGS += $(CFLAGS_libxenstore)
$(INIT_DOM0LESS_OBJS): CFLAGS += $(CFLAGS_libxenlight)
$(INIT_DOM0LESS_OBJS): CFLAGS += $(CFLAGS_libxenctrl)
$(INIT_DOM0LESS_OBJS): CFLAGS += $(CFLAGS_libxenevtchn)
init-dom0less: LDLIBS += $(call xenlibs-ldlibs,ctrl evtchn toollog store light guest foreignmemory)

.PHONY: all
all: $(TARGETS)

xen-init-dom0: $(XEN_INIT_DOM0_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(XEN_INIT_DOM0_OBJS) $(LDLIBS) $(APPEND_LDFLAGS)

init-xenstore-domain: $(INIT_XENSTORE_DOMAIN_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(INIT_XENSTORE_DOMAIN_OBJS) $(LDLIBS) $(APPEND_LDFLAGS)

init-dom0less: $(INIT_DOM0LESS_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(INIT_DOM0LESS_OBJS) $(LDLIBS) $(APPEND_LDFLAGS)

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
