XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR	= 1
MINOR	= 0
SHLIB_LDFLAGS += -Wl,--version-script=libxentoollog.map

CFLAGS	+= -Werror -Wmissing-prototypes
CFLAGS	+= -I./include

SRCS-y	+= xtl_core.c
SRCS-y	+= xtl_logger_stdio.c

LIB_OBJS := $(patsubst %.c,%.o,$(SRCS-y))
PIC_OBJS := $(patsubst %.c,%.opic,$(SRCS-y))

LIB := libxentoollog.a
ifneq ($(nosharedlibs),y)
LIB += libxentoollog.so
endif

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) libs

.PHONY: libs
libs: headers.chk $(LIB)

headers.chk: $(wildcard include/*.h)

libxentoollog.a: $(LIB_OBJS)
	$(AR) rc $@ $^

libxentoollog.so: libxentoollog.so.$(MAJOR)
	$(SYMLINK_SHLIB) $< $@
libxentoollog.so.$(MAJOR): libxentoollog.so.$(MAJOR).$(MINOR)
	$(SYMLINK_SHLIB) $< $@

libxentoollog.so.$(MAJOR).$(MINOR): $(PIC_OBJS) libxentoollog.map
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxentoollog.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $(PIC_OBJS) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_SHLIB) libxentoollog.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) libxentoollog.a $(DESTDIR)$(libdir)
	$(SYMLINK_SHLIB) libxentoollog.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxentoollog.so.$(MAJOR)
	$(SYMLINK_SHLIB) libxentoollog.so.$(MAJOR) $(DESTDIR)$(libdir)/libxentoollog.so
	$(INSTALL_DATA) include/xentoollog.h $(DESTDIR)$(includedir)

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS) $(LIB_OBJS) $(PIC_OBJS)
	rm -f libxentoollog.so.$(MAJOR).$(MINOR) libxentoollog.so.$(MAJOR)
	rm -f headers.chk

.PHONY: distclean
distclean: clean
