include $(XEN_ROOT)/tools/libfsimage/common.mk

FSLIB = fsimage.so
TARGETS += $(FSLIB)

.PHONY: all
all: $(TARGETS)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(FSDIR)/$(FS)
	$(INSTALL_PROG) $(FSLIB) $(DESTDIR)$(FSDIR)/$(FS)

.PHONY: uninstall
uninstall:
	rm -f $(addprefix $(DESTDIR)$(FSDIR)/$(FS)/, $(FSLIB))
	if [ -d $(DESTDIR)$(FSDIR)/$(FS) ]; then \
		rmdir $(DESTDIR)$(FSDIR)/$(FS); \
	fi

$(FSLIB): $(PIC_OBJS)
	$(CC) $(LDFLAGS) $(SHLIB_LDFLAGS) -o $@ $^ -lxenfsimage $(FS_LIBDEPS) $(APPEND_LDFLAGS)

-include $(DEPS_INCLUDE)
