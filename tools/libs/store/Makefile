XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR = 4
MINOR = 0

ifeq ($(CONFIG_Linux),y)
LDLIBS += -ldl
endif

SRCS-y   += xs_lib.c
SRCS-y   += xs.c

LIBHEADER = xenstore.h xenstore_lib.h

include ../libs.mk

# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h
CFLAGS += $(CFLAGS_libxentoolcore)
CFLAGS += -DXEN_LIB_STORED="\"$(XEN_LIB_STORED)\""
CFLAGS += -DXEN_RUN_STORED="\"$(XEN_RUN_STORED)\""

vpath xs_lib.c $(XEN_ROOT)/tools/xenstore
CFLAGS += -I $(XEN_ROOT)/tools/xenstore

xs.opic: CFLAGS += -DUSE_PTHREAD
ifeq ($(CONFIG_Linux),y)
xs.opic: CFLAGS += -DUSE_DLSYM
endif

.PHONY: install
install::
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)/xenstore-compat
	$(INSTALL_DATA) $(XEN_INCLUDE)/xenstore-compat/xs.h $(DESTDIR)$(includedir)/xenstore-compat/xs.h
	$(INSTALL_DATA) $(XEN_INCLUDE)/xenstore-compat/xs_lib.h $(DESTDIR)$(includedir)/xenstore-compat/xs_lib.h
	ln -sf xenstore-compat/xs.h  $(DESTDIR)$(includedir)/xs.h
	ln -sf xenstore-compat/xs_lib.h $(DESTDIR)$(includedir)/xs_lib.h

.PHONY: uninstall
uninstall::
	rm -f $(DESTDIR)$(includedir)/xs_lib.h
	rm -f $(DESTDIR)$(includedir)/xs.h
	rm -f $(DESTDIR)$(includedir)/xenstore-compat/xs_lib.h
	rm -f $(DESTDIR)$(includedir)/xenstore-compat/xs.h
	if [ -d $(DESTDIR)$(includedir)/xenstore-compat ]; then \
		rmdir --ignore-fail-on-non-empty $(DESTDIR)$(includedir)/xenstore-compat; \
	fi
