XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 1
SHLIB_LDFLAGS += -Wl,--version-script=libxengnttab.map

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -I./include $(CFLAGS_xeninclude)
CFLAGS   += $(CFLAGS_libxentoollog)

SRCS-GNTTAB            += gnttab_core.c
SRCS-GNTSHR            += gntshr_core.c

SRCS-$(CONFIG_Linux)   += $(SRCS-GNTTAB) $(SRCS-GNTSHR) linux.c
SRCS-$(CONFIG_MiniOS)  += $(SRCS-GNTTAB) gntshr_unimp.c minios.c
SRCS-$(CONFIG_FreeBSD) += gnttab_unimp.c gntshr_unimp.c
SRCS-$(CONFIG_SunOS)   += gnttab_unimp.c gntshr_unimp.c
SRCS-$(CONFIG_NetBSD)  += gnttab_unimp.c gntshr_unimp.c

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS-y))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS-y))

LIB := libxengnttab.a
ifneq ($(nosharedlibs),y)
LIB += libxengnttab.so
endif

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) libs

.PHONY: libs
libs: headers.chk $(LIB)

headers.chk: $(wildcard include/*.h)

libxengnttab.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxengnttab.so: libxengnttab.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxengnttab.so.$(MAJOR): libxengnttab.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxengnttab.so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxengnttab.map
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxengnttab.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(LDLIBS_libxentoollog) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxengnttab.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxengnttab.a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxengnttab.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxengnttab.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxengnttab.so.$(MAJOR) $(DESTDIR)$(libdir)/libxengnttab.so
	$(INSTALL_DATA) include/xengnttab.h $(DESTDIR)$(includedir)

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS) $(LIB_OBJS) $(PIC_OBJS)
	rm -f libxengnttab.so.$(MAJOR).$(MINOR) libxengnttab.so.$(MAJOR)
	rm -f headers.chk

.PHONY: distclean
distclean: clean
