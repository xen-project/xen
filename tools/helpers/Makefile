#
# tools/helpers/Makefile
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

PROGS += xen-init-dom0
ifeq ($(CONFIG_Linux),y)
PROGS += init-xenstore-domain
endif

XEN_INIT_DOM0_OBJS = xen-init-dom0.o init-dom-json.o
$(XEN_INIT_DOM0_OBJS): CFLAGS += $(CFLAGS_libxentoollog)
$(XEN_INIT_DOM0_OBJS): CFLAGS += $(CFLAGS_libxenstore)
$(XEN_INIT_DOM0_OBJS): CFLAGS += $(CFLAGS_libxenlight)

INIT_XENSTORE_DOMAIN_OBJS = init-xenstore-domain.o init-dom-json.o
$(INIT_XENSTORE_DOMAIN_OBJS): CFLAGS += $(CFLAGS_libxentoollog)
$(INIT_XENSTORE_DOMAIN_OBJS): CFLAGS += $(CFLAGS_libxenguest)
$(INIT_XENSTORE_DOMAIN_OBJS): CFLAGS += $(CFLAGS_libxenctrl)
$(INIT_XENSTORE_DOMAIN_OBJS): CFLAGS += $(CFLAGS_libxenstore)
$(INIT_XENSTORE_DOMAIN_OBJS): CFLAGS += $(CFLAGS_libxenlight)

.PHONY: all
all: $(PROGS)

xen-init-dom0: $(XEN_INIT_DOM0_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(XEN_INIT_DOM0_OBJS) $(LDLIBS_libxentoollog) $(LDLIBS_libxenstore) $(LDLIBS_libxenlight) $(APPEND_LDFLAGS)

$(INIT_XENSTORE_DOMAIN_OBJS): _paths.h

init-xenstore-domain: $(INIT_XENSTORE_DOMAIN_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(INIT_XENSTORE_DOMAIN_OBJS) $(LDLIBS_libxentoollog) $(LDLIBS_libxenstore) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenlight) $(APPEND_LDFLAGS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) xen-init-dom0 $(DESTDIR)$(LIBEXEC_BIN)
ifeq ($(CONFIG_Linux),y)
	$(INSTALL_PROG) init-xenstore-domain $(DESTDIR)$(LIBEXEC_BIN)
endif

.PHONY: clean
clean:
	$(RM) -f *.o $(PROGS) $(DEPS) _paths.h

distclean: clean

genpath-target = $(call buildmakevars2header,_paths.h)
$(eval $(genpath-target))
