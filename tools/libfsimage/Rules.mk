include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Wno-unknown-pragmas -I$(XEN_ROOT)/tools/libfsimage/common/ -DFSIMAGE_FSDIR=\"$(FSDIR)\"
CFLAGS += -Werror -D_GNU_SOURCE
LDFLAGS += -L../common/

PIC_OBJS := $(patsubst %.c,%.opic,$(LIB_SRCS-y))

FSDIR = $(libdir)/fs

FSLIB = fsimage.so

.PHONY: fs-all
fs-all: $(FSLIB)

.PHONY: fs-install
fs-install: fs-all
	$(INSTALL_DIR) $(DESTDIR)$(FSDIR)/$(FS)
	$(INSTALL_PROG) $(FSLIB) $(DESTDIR)$(FSDIR)/$(FS)

.PHONY: fs-uninstall
fs-uninstall:
	rm -f $(addprefix $(DESTDIR)$(FSDIR)/$(FS)/, $(FSLIB))
	if [ -d $(DESTDIR)$(FSDIR)/$(FS) ]; then \
		rmdir $(DESTDIR)$(FSDIR)/$(FS); \
	fi

$(FSLIB): $(PIC_OBJS)
	$(CC) $(LDFLAGS) $(SHLIB_LDFLAGS) -o $@ $^ -lfsimage $(FS_LIBDEPS) $(APPEND_LDFLAGS)

clean distclean::
	rm -f $(PIC_OBJS) $(FSLIB) $(DEPS_RM)

-include $(DEPS_INCLUDE)
