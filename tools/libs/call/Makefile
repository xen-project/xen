XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 0
SHLIB_LDFLAGS += -Wl,--version-script=libxencall.map

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -I./include $(CFLAGS_xeninclude)
CFLAGS   += $(CFLAGS_libxentoollog)

SRCS-y                 += core.c buffer.c
SRCS-$(CONFIG_Linux)   += linux.c
SRCS-$(CONFIG_FreeBSD) += freebsd.c
SRCS-$(CONFIG_SunOS)   += solaris.c
SRCS-$(CONFIG_NetBSD)  += netbsd.c
SRCS-$(CONFIG_MiniOS)  += minios.c

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS-y))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS-y))

LIB := libxencall.a
ifneq ($(nosharedlibs),y)
LIB += libxencall.so
endif

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) libs

.PHONY: libs
libs: headers.chk $(LIB)

headers.chk: $(wildcard include/*.h)

libxencall.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxencall.so: libxencall.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxencall.so.$(MAJOR): libxencall.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxencall.so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxencall.map
	$(CC) $(LDFLAGS) $(PTHREAD_LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxencall.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(LDLIBS_libxentoollog) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxencall.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxencall.a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxencall.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxencall.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxencall.so.$(MAJOR) $(DESTDIR)$(libdir)/libxencall.so
	$(INSTALL_DATA) include/xencall.h $(DESTDIR)$(includedir)

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS) $(LIB_OBJS) $(PIC_OBJS)
	rm -f libxencall.so.$(MAJOR).$(MINOR) libxencall.so.$(MAJOR)
	rm -f headers.chk

.PHONY: distclean
distclean: clean
