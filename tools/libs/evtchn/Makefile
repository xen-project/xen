XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 0
SHLIB_LDFLAGS += -Wl,--version-script=libxenevtchn.map

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -I./include $(CFLAGS_xeninclude)
CFLAGS   += $(CFLAGS_libxentoollog)

SRCS-y                 += core.c
SRCS-$(CONFIG_Linux)   += linux.c
SRCS-$(CONFIG_FreeBSD) += freebsd.c
SRCS-$(CONFIG_SunOS)   += solaris.c
SRCS-$(CONFIG_NetBSD)  += netbsd.c
SRCS-$(CONFIG_MiniOS)  += minios.c

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS-y))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS-y))

LIB := libxenevtchn.a
ifneq ($(nosharedlibs),y)
LIB += libxenevtchn.so
endif

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) libs

.PHONY: libs
libs: headers.chk $(LIB)

headers.chk: $(wildcard include/*.h)

libxenevtchn.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxenevtchn.so: libxenevtchn.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxenevtchn.so.$(MAJOR): libxenevtchn.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxenevtchn.so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxenevtchn.map
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenevtchn.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(LDLIBS_libxentoollog) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxenevtchn.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxenevtchn.a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxenevtchn.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxenevtchn.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxenevtchn.so.$(MAJOR) $(DESTDIR)$(libdir)/libxenevtchn.so
	$(INSTALL_DATA) include/xenevtchn.h $(DESTDIR)$(includedir)

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS) $(LIB_OBJS) $(PIC_OBJS)
	rm -f libxenevtchn.so.$(MAJOR).$(MINOR) libxenevtchn.so.$(MAJOR)
	rm -f headers.chk

.PHONY: distclean
distclean: clean
