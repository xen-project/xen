XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 2
SHLIB_LDFLAGS += -Wl,--version-script=libxendevicemodel.map

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -I./include $(CFLAGS_xeninclude)
CFLAGS   += $(CFLAGS_libxentoollog)
CFLAGS   += $(CFLAGS_libxentoolcore)
CFLAGS   += $(CFLAGS_libxencall)

SRCS-y                 += core.c
SRCS-$(CONFIG_Linux)   += linux.c
SRCS-$(CONFIG_FreeBSD) += compat.c
SRCS-$(CONFIG_SunOS)   += compat.c
SRCS-$(CONFIG_NetBSD)  += compat.c
SRCS-$(CONFIG_MiniOS)  += compat.c

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS-y))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS-y))

LIB := libxendevicemodel.a
ifneq ($(nosharedlibs),y)
LIB += libxendevicemodel.so
endif

PKG_CONFIG := xendevicemodel.pc
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBXENDEVICEMODEL)/include
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_CFLAGS_LOCAL = $(CFLAGS_xeninclude)

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) libs

.PHONY: libs
libs: headers.chk $(LIB) $(PKG_CONFIG_INST) $(PKG_CONFIG_LOCAL)

headers.chk: $(wildcard include/*.h)

libxendevicemodel.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxendevicemodel.so: libxendevicemodel.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxendevicemodel.so.$(MAJOR): libxendevicemodel.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxendevicemodel.so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxendevicemodel.map
	$(CC) $(LDFLAGS) $(PTHREAD_LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxendevicemodel.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(LDLIBS_libxentoollog) $(LDLIBS_libxencall) $(LDLIBS_libxentoolcore) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxendevicemodel.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxendevicemodel.a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxendevicemodel.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxendevicemodel.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxendevicemodel.so.$(MAJOR) $(DESTDIR)$(libdir)/libxendevicemodel.so
	$(INSTALL_DATA) include/xendevicemodel.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) xendevicemodel.pc $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xendevicemodel.pc
	rm -f $(DESTDIR)$(includedir)/xendevicemodel.h
	rm -f $(DESTDIR)$(libdir)/libxendevicemodel.so
	rm -f $(DESTDIR)$(libdir)/libxendevicemodel.so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxendevicemodel.so.$(MAJOR).$(MINOR)
	rm -f $(DESTDIR)$(libdir)/libxendevicemodel.a

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS_RM) $(LIB_OBJS) $(PIC_OBJS)
	rm -f libxendevicemodel.so.$(MAJOR).$(MINOR) libxendevicemodel.so.$(MAJOR)
	rm -f headers.chk
	rm -f xendevicemodel.pc

.PHONY: distclean
distclean: clean
