XEN_ROOT = ..
MINI_OS = $(XEN_ROOT)/extras/mini-os

export XEN_OS=MiniOS

export stubdom=y
export debug=y
include $(XEN_ROOT)/Config.mk

override CONFIG_QEMU=ioemu

IOEMU_OPTIONS=--disable-sdl --disable-opengl --disable-gfx-check --disable-vnc-tls --disable-brlapi --disable-kqemu
ZLIB_VERSION=1.2.3
LIBPCI_VERSION=2.2.9
NEWLIB_VERSION=1.16.0
LWIP_VERSION=1.3.0
GRUB_VERSION=0.97

WGET=wget -c

GNU_TARGET_ARCH:=$(XEN_TARGET_ARCH)
ifeq ($(XEN_TARGET_ARCH),x86_32)
GNU_TARGET_ARCH:=i686
endif

ifeq ($(GNU_TARGET_ARCH), i686)
TARGET_CFLAGS=
NEWLIB_CFLAGS+=-D_I386MACH_ALLOW_HW_INTERRUPTS
STUBDOM_SUPPORTED=1
endif
ifeq ($(GNU_TARGET_ARCH), x86_64)
TARGET_CFLAGS=-mno-red-zone
NEWLIB_CFLAGS+=-D_I386MACH_ALLOW_HW_INTERRUPTS
STUBDOM_SUPPORTED=1
endif
ifeq ($(GNU_TARGET_ARCH), ia64)
TARGET_CFLAGS=-mconstant-gp
endif

CROSS_ROOT=cross-root-$(GNU_TARGET_ARCH)
CROSS_PREFIX=$(CURDIR)/$(CROSS_ROOT)

# Disable PIE/SSP if GCC supports them. They can break us.
TARGET_CFLAGS += $(CFLAGS)
TARGET_CPPFLAGS += $(CPPFLAGS)
TARGET_CFLAGS += $(call cc-option,$(CC),-nopie,)
TARGET_CFLAGS += $(call cc-option,$(CC),-fno-stack-protector,)
TARGET_CFLAGS += $(call cc-option,$(CC),-fno-stack-protector-all,)

# Do not use host headers and libs
GCC_INSTALL = $(shell gcc -print-search-dirs | sed -n -e 's/install: \(.*\)/\1/p')
TARGET_CPPFLAGS += -U __linux__ -U __FreeBSD__ -U __sun__
TARGET_CPPFLAGS += -nostdinc
TARGET_CPPFLAGS += -isystem $(CURDIR)/$(MINI_OS)/include/posix
TARGET_CPPFLAGS += -isystem $(CROSS_PREFIX)/$(GNU_TARGET_ARCH)-xen-elf/include
TARGET_CPPFLAGS += -isystem $(GCC_INSTALL)include
TARGET_CPPFLAGS += -isystem $(CURDIR)/lwip/src/include
TARGET_CPPFLAGS += -isystem $(CURDIR)/lwip/src/include/ipv4
TARGET_CPPFLAGS += -I$(CURDIR)/include

TARGET_LDFLAGS += -nostdlib -L$(CROSS_PREFIX)/$(GNU_TARGET_ARCH)-xen-elf/lib

TARGETS=ioemu c caml grub

.PHONY: all
all: build
ifeq ($(STUBDOM_SUPPORTED),1)
build: ioemu-stubdom c-stubdom pv-grub
else
build:
endif

##############
# Cross-newlib
##############

newlib-$(NEWLIB_VERSION).tar.gz:
	$(WGET) ftp://sources.redhat.com/pub/newlib/$@

newlib-$(NEWLIB_VERSION): newlib-$(NEWLIB_VERSION).tar.gz
	tar xzf $<
	patch -d $@ -p0 < newlib.patch
	touch $@

NEWLIB_STAMPFILE=$(CROSS_ROOT)/$(GNU_TARGET_ARCH)-xen-elf/lib/libc.a
.PHONY: cross-newlib
cross-newlib: $(NEWLIB_STAMPFILE)
$(NEWLIB_STAMPFILE): mk-headers newlib-$(NEWLIB_VERSION)
	mkdir -p newlib-build
	( cd newlib-build && \
	  CC_FOR_TARGET="$(CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) $(NEWLIB_CFLAGS)" AR_FOR_TARGET=$(AR) LD_FOR_TARGET=$(LD) RANLIB_FOR_TARGET=$(RANLIB) ../newlib-$(NEWLIB_VERSION)/configure --prefix=$(CROSS_PREFIX) --verbose --target=$(GNU_TARGET_ARCH)-xen-elf --enable-newlib-io-long-long --disable-multilib && \
	  $(MAKE) && \
	  DESTDIR= $(MAKE) install )

############
# Cross-zlib
############

zlib-$(ZLIB_VERSION).tar.gz:
	$(WGET) http://www.zlib.net/$@

ZLIB_STAMPFILE=$(CROSS_ROOT)/$(GNU_TARGET_ARCH)-xen-elf/lib/libz.a
.PHONY: cross-zlib
cross-zlib: $(ZLIB_STAMPFILE)
$(ZLIB_STAMPFILE): zlib-$(ZLIB_VERSION).tar.gz $(NEWLIB_STAMPFILE)
	tar xzf $<
	( cd zlib-$(ZLIB_VERSION) && \
	  CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" CC=$(CC) ./configure --prefix=$(CROSS_PREFIX)/$(GNU_TARGET_ARCH)-xen-elf && \
	  $(MAKE) libz.a && \
	  $(MAKE) install )

##############
# Cross-libpci
##############

pciutils-$(LIBPCI_VERSION).tar.bz2:
	$(WGET) http://www.kernel.org/pub/software/utils/pciutils/$@

pciutils-$(LIBPCI_VERSION): pciutils-$(LIBPCI_VERSION).tar.bz2
	tar xjf $<
	patch -d $@ -p1 < pciutils.patch
	touch $@

LIBPCI_STAMPFILE=$(CROSS_ROOT)/$(GNU_TARGET_ARCH)-xen-elf/lib/libpci.a
.PHONY: cross-libpci
cross-libpci: $(LIBPCI_STAMPFILE)
$(LIBPCI_STAMPFILE): pciutils-$(LIBPCI_VERSION) $(NEWLIB_STAMPFILE) $(ZLIB_STAMPFILE)
	( cd pciutils-$(LIBPCI_VERSION) && \
	  cp ../libpci.config.h lib/config.h && \
	  echo '#define PCILIB_VERSION "$(LIBPCI_VERSION)"' >> lib/config.h && \
	  cp ../libpci.config.mak lib/config.mk && \
	  $(MAKE) CC="$(CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -I$(realpath $(MINI_OS)/include)" lib/libpci.a && \
	  $(INSTALL_DATA) lib/libpci.a $(CROSS_PREFIX)/$(GNU_TARGET_ARCH)-xen-elf/lib/ && \
	  $(INSTALL_DIR) $(CROSS_PREFIX)/$(GNU_TARGET_ARCH)-xen-elf/include/pci && \
	  $(INSTALL_DATA) lib/{config,header,pci,types}.h $(CROSS_PREFIX)/$(GNU_TARGET_ARCH)-xen-elf/include/pci/ \
	)

######
# lwIP
######

lwip-$(LWIP_VERSION).tar.gz:
	$(WGET) http://download.savannah.gnu.org/releases/lwip/$@

lwip: lwip-$(LWIP_VERSION).tar.gz
	tar xzf $<
	patch -d $@ -p0 < lwip.patch-cvs
	touch $@

#######
# Links
#######

.PHONY: $(CROSS_ROOT)
$(CROSS_ROOT): cross-newlib cross-zlib cross-libpci

mk-headers:
	mkdir -p include/xen && \
          ln -sf $(addprefix ../../,$(wildcard $(XEN_ROOT)/xen/include/public/*.h)) include/xen && \
          ln -sf $(addprefix ../../$(XEN_ROOT)/xen/include/public/,arch-ia64 arch-x86 hvm io xsm) include/xen && \
          ( [ -h include/xen/sys ] || ln -sf ../../$(XEN_ROOT)/tools/include/xen-sys/MiniOS include/xen/sys ) && \
	  mkdir -p include/xen-foreign && \
	  ln -sf $(addprefix ../../,$(wildcard $(XEN_ROOT)/tools/include/xen-foreign/*)) include/xen-foreign/ && \
	  $(MAKE) -C include/xen-foreign/ && \
	  ( [ -h include/xen/foreign ] || ln -sf ../xen-foreign include/xen/foreign )
	mkdir -p libxc
	[ -h libxc/Makefile ] || ( cd libxc && \
	  ln -sf ../$(XEN_ROOT)/tools/libxc/*.h . && \
	  ln -sf ../$(XEN_ROOT)/tools/libxc/*.c . && \
	  ln -sf ../$(XEN_ROOT)/tools/libxc/Makefile . )
	mkdir -p libxc/$(XEN_TARGET_ARCH)
	[ -h libxc/$(XEN_TARGET_ARCH) ] || ( cd libxc/$(XEN_TARGET_ARCH) && \
	  ln -sf ../$(XEN_ROOT)/tools/libxc/$(XEN_TARGET_ARCH)/*.c . && \
	  ln -sf ../$(XEN_ROOT)/tools/libxc/$(XEN_TARGET_ARCH)/*.h . && \
	  ln -sf ../$(XEN_ROOT)/tools/libxc/$(XEN_TARGET_ARCH)/Makefile . )
	mkdir -p ioemu
ifeq ($(CONFIG_QEMU),ioemu)
	[ -h ioemu/Makefile ] || ( cd ioemu && \
	  ln -sf ../$(XEN_ROOT)/tools/ioemu/* .)
else
	[ -h ioemu/Makefile ] || ( cd ioemu && \
	  ln -sf $(CONFIG_QEMU)/* . && \
          rm -fr i386-dm && \
          rm -fr i386-stubdom && \
          mkdir i386-dm && \
          mkdir i386-stubdom && \
	  ln -sf $(CONFIG_QEMU)/i386-dm/* i386-dm/ && \
	  ln -sf $(CONFIG_QEMU)/i386-stubdom/* i386-stubdom/ )
endif
	[ ! -h ioemu/config-host.h ] || rm -f ioemu/config-host.h
	[ ! -h ioemu/config-host.mak ] || rm -f ioemu/config-host.mak
	$(MAKE) -C $(MINI_OS) links
	touch mk-headers

TARGETS_MINIOS=$(addprefix mini-os-,$(TARGETS))
$(TARGETS_MINIOS): mini-os-%:
	[ -d $@ ] || \
	for i in $$(cd $(MINI_OS) ; find . -type d) ; do \
                mkdir -p $@/$$i ; \
	done

#######
# libxc
#######

.PHONY: libxc
libxc: libxc/libxenctrl.a libxc/libxenguest.a
libxc/libxenctrl.a libxc/libxenguest.a:: cross-zlib
	CPPFLAGS="$(TARGET_CPPFLAGS)" CFLAGS="$(TARGET_CFLAGS)" $(MAKE) -C libxc

#######
# ioemu
#######

.PHONY: ioemu
ioemu: cross-zlib cross-libpci libxc
ifeq ($(CONFIG_QEMU),ioemu)
	[ -f ioemu/config-host.mak ] || \
	  ( cd ioemu ; \
          XEN_TARGET_ARCH=$(XEN_TARGET_ARCH) CFLAGS="$(TARGET_CFLAGS)" sh configure --prefix=/usr --enable-stubdom $(IOEMU_OPTIONS))
	CPPFLAGS="$(TARGET_CPPFLAGS)" $(MAKE) -C ioemu LWIPDIR=$(CURDIR)/lwip TOOLS=
else
	[ -f ioemu/config-host.mak ] || \
	  ( cd ioemu ; \
          CONFIG_STUBDOM=yes XEN_ROOT=$(abspath $(XEN_ROOT)) XEN_TARGET_ARCH=$(XEN_TARGET_ARCH) CFLAGS="$(TARGET_CFLAGS)" sh ./xen-setup --cc=$(CC) --disable-gcc-check $(IOEMU_OPTIONS))
	CPPFLAGS= TARGET_CPPFLAGS="$(TARGET_CPPFLAGS)" $(MAKE) -C ioemu LWIPDIR=$(CURDIR)/lwip TOOLS= CONFIG_STUBDOM=yes
endif

######
# caml
######

.PHONY: caml
caml: $(CROSS_ROOT)
	CPPFLAGS="$(TARGET_CPPFLAGS)" CFLAGS="$(TARGET_CFLAGS)" $(MAKE) -C $@ LWIPDIR=$(CURDIR)/lwip 

###
# C
###

.PHONY: c
c: $(CROSS_ROOT)
	CPPFLAGS="$(TARGET_CPPFLAGS)" CFLAGS="$(TARGET_CFLAGS)" $(MAKE) -C $@ LWIPDIR=$(CURDIR)/lwip 

######
# Grub
######

grub-$(GRUB_VERSION).tar.gz:
	$(WGET) ftp://alpha.gnu.org/gnu/grub/$@

grub-upstream: grub-$(GRUB_VERSION).tar.gz
	tar xzf $<
	mv grub-$(GRUB_VERSION) $@
	for i in grub.patches/* ; do \
		patch -d $@ -p1 < $$i ; \
	done

.PHONY: grub
grub: grub-upstream $(CROSS_ROOT)
	CPPFLAGS="$(TARGET_CPPFLAGS)" CFLAGS="$(TARGET_CFLAGS)" $(MAKE) -C $@

########
# minios
########

.PHONY: ioemu-stubdom
ifeq ($(CONFIG_QEMU),ioemu)
ioemu-stubdom: APP_OBJS=$(CURDIR)/ioemu/i386-dm-stubdom/qemu.a $(CURDIR)/ioemu/i386-dm-stubdom/libqemu.a
else
ioemu-stubdom: APP_OBJS=$(CURDIR)/ioemu/i386-stubdom/qemu.a $(CURDIR)/ioemu/i386-stubdom/libqemu.a $(CURDIR)/ioemu/libqemu_common.a
endif
ioemu-stubdom: mini-os-ioemu lwip libxc ioemu
	DEF_CPPFLAGS="$(TARGET_CPPFLAGS)" DEF_CFLAGS="-DCONFIG_QEMU $(TARGET_CFLAGS)" DEF_LDFLAGS="$(TARGET_LDFLAGS)" $(MAKE) -C $(MINI_OS) OBJ_DIR=$(CURDIR)/$< LWIPDIR=$(CURDIR)/lwip APP_OBJS="$(APP_OBJS)"

CAMLLIB = $(shell ocamlc -where)
.PHONY: caml-stubdom
caml-stubdom: mini-os-caml lwip libxc caml
	DEF_CPPFLAGS="$(TARGET_CPPFLAGS)" DEF_CFLAGS="-DCONFIG_CAML $(TARGET_CFLAGS)" DEF_LDFLAGS="$(TARGET_LDFLAGS)" $(MAKE) -C $(MINI_OS) OBJ_DIR=$(CURDIR)/$< LWIPDIR=$(CURDIR)/lwip APP_OBJS="$(CURDIR)/caml/main-caml.o $(CURDIR)/caml/caml.o $(CAMLLIB)/libasmrun.a"

.PHONY: c-stubdom
c-stubdom: mini-os-c lwip libxc c
	DEF_CPPFLAGS="$(TARGET_CPPFLAGS)" DEF_CFLAGS="-DCONFIG_C $(TARGET_CFLAGS)" DEF_LDFLAGS="$(TARGET_LDFLAGS)" $(MAKE) -C $(MINI_OS) OBJ_DIR=$(CURDIR)/$< LWIPDIR=$(CURDIR)/lwip APP_OBJS=$(CURDIR)/c/main.a

.PHONY: pv-grub
pv-grub: mini-os-grub libxc grub
	DEF_CPPFLAGS="$(TARGET_CPPFLAGS)" DEF_CFLAGS="-DCONFIG_GRUB $(TARGET_CFLAGS)" DEF_LDFLAGS="$(TARGET_LDFLAGS)" $(MAKE) -C $(MINI_OS) OBJ_DIR=$(CURDIR)/$< APP_OBJS=$(CURDIR)/grub/main.a

#########
# install
#########

ifeq ($(STUBDOM_SUPPORTED),1)
install: install-ioemu install-grub
else
install:
endif

install-ioemu: ioemu-stubdom
	$(INSTALL_DIR) "$(DESTDIR)/usr/lib/xen/bin"
	$(INSTALL_PROG) stubdom-dm "$(DESTDIR)/usr/lib/xen/bin"
	$(INSTALL_DIR) "$(DESTDIR)/usr/lib/xen/boot"
	$(INSTALL_PROG) mini-os-ioemu/mini-os.gz "$(DESTDIR)/usr/lib/xen/boot/ioemu-stubdom.gz"

install-grub: pv-grub
	$(INSTALL_DIR) "$(DESTDIR)/usr/lib/xen/boot"
	$(INSTALL_PROG) mini-os-grub/mini-os.gz "$(DESTDIR)/usr/lib/xen/boot/pv-grub.gz"

#######
# clean
#######

# Only clean the libxc/ioemu/mini-os part
.PHONY: clean
clean:
	rm -fr mini-os-ioemu
	rm -fr mini-os-c
	rm -fr mini-os-caml
	rm -fr mini-os-grub
	$(MAKE) -C caml clean
	$(MAKE) -C c clean
	$(MAKE) -C grub clean
	[ ! -d libxc ] || $(MAKE) -C libxc clean
	[ ! -d ioemu ] || $(MAKE) -C ioemu clean

# clean the cross-compilation result
.PHONY: crossclean
crossclean: clean
	rm -fr $(CROSS_ROOT)
	rm -fr newlib-build
	rm -fr zlib-$(ZLIB_VERSION) pciutils-$(LIBPCI_VERSION)
	rm -fr libxc ioemu
	rm -f mk-headers

# clean patched sources
.PHONY: patchclean
patchclean: crossclean
	rm -fr newlib-$(NEWLIB_VERSION)
	rm -fr lwip
	rm -fr grub-upstream

# clean downloads
.PHONY: downloadclean
downloadclean: patchclean
	rm -f newlib-$(NEWLIB_VERSION).tar.gz
	rm -f zlib-$(ZLIB_VERSION).tar.gz
	rm -f pciutils-$(LIBPCI_VERSION).tar.bz2
	rm -f grub-$(GRUB_VERSION).tar.gz
	rm -f lwip-$(LWIP_VERSION).tar.gz

.PHONY: distclean
distclean: downloadclean
