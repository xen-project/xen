XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 0
SHLIB_LDFLAGS += -Wl,--version-script=libxendevicemodel.map

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -I./include $(CFLAGS_xeninclude)
CFLAGS   += $(CFLAGS_libxentoollog)
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

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) libs

.PHONY: libs
libs: headers.chk $(LIB)

headers.chk: $(wildcard include/*.h)

libxendevicemodel.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxendevicemodel.so: libxendevicemodel.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxendevicemodel.so.$(MAJOR): libxendevicemodel.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxendevicemodel.so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxendevicemodel.map
	$(CC) $(LDFLAGS) $(PTHREAD_LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxendevicemodel.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(LDLIBS_libxentoollog) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxendevicemodel.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxendevicemodel.a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxendevicemodel.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxendevicemodel.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxendevicemodel.so.$(MAJOR) $(DESTDIR)$(libdir)/libxendevicemodel.so
	$(INSTALL_DATA) include/xendevicemodel.h $(DESTDIR)$(includedir)

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS) $(LIB_OBJS) $(PIC_OBJS)
	rm -f libxendevicemodel.so.$(MAJOR).$(MINOR) libxendevicemodel.so.$(MAJOR)
	rm -f headers.chk

.PHONY: distclean
distclean: clean
