XEN_ROOT := $(CURDIR)/../../../
include $(XEN_ROOT)/tools/Rules.mk

MAJOR              = 1.0
MINOR              = 0
LIBNAME            = libblktapctl
LIBSONAME          = $(LIBNAME).so.$(MAJOR)

IBIN               = tap-ctl

CFLAGS            += -Werror
CFLAGS            += -Wno-unused
CFLAGS            += -I../include -I../drivers
CFLAGS            += $(CFLAGS_xeninclude)
CFLAGS            += $(CFLAGS_libxenctrl)
CFLAGS            += -D_GNU_SOURCE
CFLAGS            += -DTAPCTL

CTL_OBJS  := tap-ctl-ipc.o
CTL_OBJS  += tap-ctl-list.o
CTL_OBJS  += tap-ctl-allocate.o
CTL_OBJS  += tap-ctl-free.o
CTL_OBJS  += tap-ctl-create.o
CTL_OBJS  += tap-ctl-destroy.o
CTL_OBJS  += tap-ctl-spawn.o
CTL_OBJS  += tap-ctl-attach.o
CTL_OBJS  += tap-ctl-detach.o
CTL_OBJS  += tap-ctl-open.o
CTL_OBJS  += tap-ctl-close.o
CTL_OBJS  += tap-ctl-pause.o
CTL_OBJS  += tap-ctl-unpause.o
CTL_OBJS  += tap-ctl-major.o
CTL_OBJS  += tap-ctl-check.o

CTL_PICS  = $(patsubst %.o,%.opic,$(CTL_OBJS))

OBJS = $(CTL_OBJS) tap-ctl.o
PICS = $(CTL_PICS)

LIB_STATIC = $(LIBNAME).a
LIB_SHARED = $(LIBSONAME).$(MINOR)
IBIN = tap-ctl

PKG_CONFIG := xenblktapctl.pc
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_BLKTAP2)/include
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_CFLAGS_LOCAL = $(CFLAGS_xeninclude) $(CFLAGS_libxenctrl)

all: build

build: $(IBIN) $(LIB_STATIC) $(LIB_SHARED) $(PKG_CONFIG_INST) $(PKG_CONFIG_LOCAL)

$(LIBNAME).so: $(LIBSONAME)
	ln -sf $< $@

$(LIBSONAME): $(LIB_SHARED)
	ln -sf $< $@

tap-ctl: tap-ctl.o $(LIBNAME).so
	$(CC) $(LDFLAGS) -o $@ $^ $(APPEND_LDFLAGS)

$(LIB_STATIC): $(CTL_OBJS)
	$(AR) r $@ $^

$(LIB_SHARED): $(CTL_PICS)
	$(CC) $(LDFLAGS) -fPIC  -Wl,$(SONAME_LDFLAG) -Wl,$(LIBSONAME) $(SHLIB_LDFLAGS) -rdynamic $^ -o $@  $(APPEND_LDFLAGS)

install: build
	$(INSTALL_DIR) -p $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) $(IBIN) $(DESTDIR)$(sbindir)
	$(INSTALL_DATA) $(LIB_STATIC) $(DESTDIR)$(libdir)
	$(INSTALL_PROG) $(LIB_SHARED) $(DESTDIR)$(libdir)
	ln -sf $(LIBSONAME) $(DESTDIR)$(libdir)/$(LIBNAME).so
	ln -sf $(LIB_SHARED) $(DESTDIR)$(libdir)/$(LIBSONAME)
	$(INSTALL_DATA) xenblktapctl.pc $(DESTDIR)$(PKG_INSTALLDIR)

clean:
	rm -f $(OBJS) $(PICS) $(DEPS_RM) $(IBIN) $(LIB_STATIC) $(LIB_SHARED)
	rm -f $(LIBNAME).so $(LIBSONAME)
	rm -f *~
	rm -f xenblktapctl.pc

uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xenblktapctl.pc
	rm -f $(DESTDIR)$(libdir)/$(LIBSONAME)
	rm -f $(DESTDIR)$(libdir)/$(LIBNAME).so
	rm -f $(addprefix $(DESTDIR)$(libdir)/, $(LIB_SHARED))
	rm -f $(addprefix $(DESTDIR)$(libdir)/, $(LIB_STATIC))
	rm -f $(addprefix $(DESTDIR)$(sbindir)/, $(IBIN))

distclean: clean

.PHONY: all build clean distclean install uninstall

-include $(DEPS_INCLUDE)
