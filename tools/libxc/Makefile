XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 3.0
MINOR    = 0

CTRL_SRCS-y       :=
CTRL_SRCS-y       += xc_core.c
CTRL_SRCS-$(CONFIG_X86) += xc_core_x86.c
CTRL_SRCS-$(CONFIG_IA64) += xc_core_ia64.c
CTRL_SRCS-y       += xc_domain.c
CTRL_SRCS-y       += xc_evtchn.c
CTRL_SRCS-y       += xc_misc.c
CTRL_SRCS-y       += xc_acm.c   
CTRL_SRCS-y       += xc_physdev.c
CTRL_SRCS-y       += xc_private.c
CTRL_SRCS-y       += xc_sedf.c
CTRL_SRCS-y       += xc_csched.c
CTRL_SRCS-y       += xc_tbuf.c
CTRL_SRCS-y       += xc_resume.c
CTRL_SRCS-$(CONFIG_X86) += xc_pagetab.c
CTRL_SRCS-$(CONFIG_Linux) += xc_linux.c
CTRL_SRCS-$(CONFIG_SunOS) += xc_solaris.c
CTRL_SRCS-$(CONFIG_X86_Linux) += xc_ptrace.c xc_ptrace_core.c

GUEST_SRCS-y :=
GUEST_SRCS-y += xg_private.c
GUEST_SRCS-$(CONFIG_MIGRATE) += xc_linux_restore.c xc_linux_save.c
GUEST_SRCS-$(CONFIG_HVM) += xc_hvm_build.c xc_hvm_restore.c xc_hvm_save.c

# symlink libelf from xen/common/libelf/
LIBELF_SRCS := libelf-tools.c libelf-loader.c
LIBELF_SRCS += libelf-dominfo.c libelf-relocate.c

libelf-tools.o: libelf-tools.c libelf-private.h
libelf-loader.o: libelf-loader.c libelf-private.h
libelf-dominfo.o: libelf-dominfo.c libelf-private.h
libelf-relocate.o: libelf-relocate.c libelf-private.h

$(LIBELF_SRCS) libelf-private.h:
	ln -s ../../xen/common/libelf/$@ $@

# add libelf bits to libxc
GUEST_SRCS-y += $(LIBELF_SRCS)

# new domain builder
GUEST_SRCS-y += xc_dom_core.c xc_dom_boot.c
GUEST_SRCS-y += xc_dom_elfloader.c
GUEST_SRCS-y += xc_dom_binloader.c
GUEST_SRCS-y += xc_dom_x86.c
GUEST_SRCS-y += xc_dom_ia64.c

GUEST_SRCS-$(CONFIG_X86)     += xc_dom_compat_linux.c
GUEST_SRCS-$(CONFIG_IA64)    += xc_dom_compat_linux.c

-include $(XEN_TARGET_ARCH)/Makefile

CFLAGS   += -Werror -Wmissing-prototypes
CFLAGS   += -fno-strict-aliasing
CFLAGS   += $(INCLUDES) -I.

# Define this to make it possible to run valgrind on code linked with these
# libraries.
#CFLAGS   += -DVALGRIND -O0 -ggdb3

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
LDFLAGS  += -L.
DEPS     = .*.d

CTRL_LIB_OBJS := $(patsubst %.c,%.o,$(CTRL_SRCS-y))
CTRL_PIC_OBJS := $(patsubst %.c,%.opic,$(CTRL_SRCS-y))

GUEST_LIB_OBJS := $(patsubst %.c,%.o,$(GUEST_SRCS-y))
GUEST_PIC_OBJS := $(patsubst %.c,%.opic,$(GUEST_SRCS-y))

LIB := libxenctrl.a
LIB += libxenctrl.so libxenctrl.so.$(MAJOR) libxenctrl.so.$(MAJOR).$(MINOR)

LIB += libxenguest.a
LIB += libxenguest.so libxenguest.so.$(MAJOR) libxenguest.so.$(MAJOR).$(MINOR)

.PHONY: all
all: build

.PHONY: build
build: check-for-zlib mk-symlinks
	$(MAKE) $(LIB)

.PHONY: check-for-zlib
check-for-zlib:
	@if [ ! -e /usr/include/zlib.h ]; then \
	echo "***********************************************************"; \
	echo "ERROR: install zlib header files (http://www.gzip.org/zlib)"; \
	echo "***********************************************************"; \
	false; \
	fi

.PHONY: install
install: build
	[ -d $(DESTDIR)/usr/$(LIBDIR) ] || $(INSTALL_DIR) $(DESTDIR)/usr/$(LIBDIR)
	[ -d $(DESTDIR)/usr/include ] || $(INSTALL_DIR) $(DESTDIR)/usr/include
	$(INSTALL_PROG) libxenctrl.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) libxenctrl.a $(DESTDIR)/usr/$(LIBDIR)
	ln -sf libxenctrl.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)/libxenctrl.so.$(MAJOR)
	ln -sf libxenctrl.so.$(MAJOR) $(DESTDIR)/usr/$(LIBDIR)/libxenctrl.so
	$(INSTALL_DATA) xenctrl.h $(DESTDIR)/usr/include

	$(INSTALL_PROG) libxenguest.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) libxenguest.a $(DESTDIR)/usr/$(LIBDIR)
	ln -sf libxenguest.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)/libxenguest.so.$(MAJOR)
	ln -sf libxenguest.so.$(MAJOR) $(DESTDIR)/usr/$(LIBDIR)/libxenguest.so
	$(INSTALL_DATA) xenguest.h $(DESTDIR)/usr/include

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

.PHONY: clean
clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS) xen \
            $(CTRL_LIB_OBJS) $(CTRL_PIC_OBJS) \
            $(GUEST_LIB_OBJS) $(GUEST_PIC_OBJS)

.PHONY: rpm
rpm: build
	rm -rf staging
	mkdir staging
	mkdir staging/i386
	rpmbuild --define "staging$$PWD/staging" --define '_builddir.' \
		--define "_rpmdir$$PWD/staging" -bb rpm.spec
	mv staging/i386/*.rpm .
	rm -rf staging

# libxenctrl

libxenctrl.a: $(CTRL_LIB_OBJS)
	$(AR) rc $@ $^

libxenctrl.so: libxenctrl.so.$(MAJOR)
	ln -sf $< $@
libxenctrl.so.$(MAJOR): libxenctrl.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenctrl.so.$(MAJOR).$(MINOR): $(CTRL_PIC_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenctrl.so.$(MAJOR) $(SHLIB_CFLAGS) -o $@ $^ -lpthread

# libxenguest

libxenguest.a: $(GUEST_LIB_OBJS)
	$(AR) rc $@ $^

libxenguest.so: libxenguest.so.$(MAJOR)
	ln -sf $< $@
libxenguest.so.$(MAJOR): libxenguest.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenguest.so.$(MAJOR).$(MINOR): $(GUEST_PIC_OBJS) libxenctrl.so
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenguest.so.$(MAJOR) $(SHLIB_CFLAGS) -o $@ $(GUEST_PIC_OBJS) -lz -lxenctrl -lpthread

-include $(DEPS)

