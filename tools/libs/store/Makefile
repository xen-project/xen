XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR = 4
MINOR = 0
version-script := libxenstore.map

ifeq ($(CONFIG_Linux),y)
LDLIBS += -ldl
endif

OBJS-y   += xs.o

LIBHEADER = xenstore.h xenstore_lib.h

include ../libs.mk

# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h
CFLAGS += $(CFLAGS_libxentoolcore)

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
