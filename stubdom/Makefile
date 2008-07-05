XEN_ROOT = ..
MINI_OS = $(XEN_ROOT)/extras/mini-os

export XEN_OS=MiniOS

export stubdom=y
export debug=y
include $(XEN_ROOT)/Config.mk

IOEMU_OPTIONS=--disable-vnc-tls 
ZLIB_VERSION=1.2.3
LIBPCI_VERSION=2.2.9
NEWLIB_DATE=2008-01-01
LWIP_DATE=2008-06-01
GRUB_DATE=2008-06-01

WGET=wget -c

GNU_TARGET_ARCH:=$(XEN_TARGET_ARCH)
ifeq ($(XEN_TARGET_ARCH),x86_32)
GNU_TARGET_ARCH:=i686
endif

ifeq ($(GNU_TARGET_ARCH), i686)
TARGET_CFLAGS=
NEWLIB_CFLAGS+=-D_I386MACH_ALLOW_HW_INTERRUPTS
endif
ifeq ($(GNU_TARGET_ARCH), x86_64)
TARGET_CFLAGS=-mno-red-zone
NEWLIB_CFLAGS+=-D_I386MACH_ALLOW_HW_INTERRUPTS
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
TARGET_CFLAGS += -nostdinc
TARGET_CPPFLAGS += -isystem $(realpath $(MINI_OS)/include/posix)
TARGET_CPPFLAGS += -isystem $(CROSS_PREFIX)/$(GNU_TARGET_ARCH)-xen-elf/include
TARGET_CPPFLAGS += -isystem $(GCC_INSTALL)include

TARGET_LDFLAGS += -nostdlib -L$(CROSS_PREFIX)/$(GNU_TARGET_ARCH)-xen-elf/lib

TARGETS=ioemu c caml grub

.PHONY: all
all: ioemu-stubdom c-stubdom pv-grub

##############
# Cross-newlib
##############

newlib-cvs:
	cvs -z 9 -d :pserver:anoncvs@sources.redhat.com:/cvs/src co -D $(NEWLIB_DATE) newlib
	mv src newlib-cvs
	patch -d $@ -p0 < newlib.patch

NEWLIB_STAMPFILE=$(CROSS_ROOT)/$(GNU_TARGET_ARCH)-xen-elf/lib/libc.a
.PHONY: cross-newlib
cross-newlib: $(NEWLIB_STAMPFILE)
$(NEWLIB_STAMPFILE): newlib-cvs
	mkdir -p newlib-build
	( cd newlib-build && \
	  CC_FOR_TARGET="$(CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) $(NEWLIB_CFLAGS)" AR_FOR_TARGET=$(AR) LD_FOR_TARGET=$(LD) RANLIB_FOR_TARGET=$(RANLIB) ../newlib-cvs/configure --prefix=$(CROSS_PREFIX) --verbose --target=$(GNU_TARGET_ARCH)-xen-elf --enable-newlib-io-long-long --disable-multilib && \
	  $(MAKE) && \
	  $(MAKE) install )

############
# Cross-zlib
############

zlib-$(ZLIB_VERSION).tar.gz:
	$(WGET) http://www.zlib.net/zlib-$(ZLIB_VERSION).tar.gz

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
	$(WGET) http://www.kernel.org/pub/software/utils/pciutils/pciutils-$(LIBPCI_VERSION).tar.bz2

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

lwip-cvs:
	cvs -z 9 -d :pserver:anonymous@cvs.savannah.nongnu.org:/sources/lwip co -D $(LWIP_DATE) -d $@ lwip

#######
# Links
#######

.PHONY: $(CROSS_ROOT)
$(CROSS_ROOT): cross-newlib cross-zlib cross-libpci

.PHONY: mk-symlinks
mk-symlinks:
	[ -h include ] || ln -sf ../tools/include .
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
	[ -h ioemu/Makefile ] || ( cd ioemu && \
	  ln -sf ../$(XEN_ROOT)/tools/ioemu/* . && \
	  ([ ! -h config-host.h ] || rm -f config-host.h) && \
	  ([ ! -h config-host.mak ] || rm -f config-host.mak) )
	$(MAKE) -C $(MINI_OS) links

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
libxc/libxenctrl.a libxc/libxenguest.a:: cross-zlib mk-symlinks
	CPPFLAGS="$(TARGET_CPPFLAGS)" CFLAGS="$(TARGET_CFLAGS)" $(MAKE) -C libxc

#######
# ioemu
#######

.PHONY: ioemu
ioemu: cross-zlib cross-libpci mk-symlinks libxc
	[ -f ioemu/config-host.mak ] || \
	  ( cd ioemu ; \
          XEN_TARGET_ARCH=$(XEN_TARGET_ARCH) CFLAGS="$(TARGET_CFLAGS)" sh configure --prefix=/usr --enable-stubdom $(IOEMU_OPTIONS))
	CPPFLAGS="$(TARGET_CPPFLAGS)" $(MAKE) -C ioemu LWIPDIR=$(CURDIR)/lwip-cvs

######
# caml
######

.PHONY: caml
caml: cross-newlib mk-symlinks
	CPPFLAGS="$(TARGET_CPPFLAGS)" CFLAGS="$(TARGET_CFLAGS)" $(MAKE) -C $@ LWIPDIR=$(CURDIR)/lwip-cvs 

###
# C
###

.PHONY: c
c: cross-newlib mk-symlinks
	CPPFLAGS="$(TARGET_CPPFLAGS)" CFLAGS="$(TARGET_CFLAGS)" $(MAKE) -C $@ LWIPDIR=$(CURDIR)/lwip-cvs 

######
# Grub
######

grub-cvs:
	cvs -z 9 -d :pserver:anonymous@cvs.sv.gnu.org:/sources/grub co -D $(GRUB_DATE) -d $@ grub
	for i in grub.patches/* ; do \
		patch -d $@ -p1 < $$i ; \
	done

.PHONY: grub
grub: grub-cvs cross-newlib mk-symlinks
	CPPFLAGS="$(TARGET_CPPFLAGS)" CFLAGS="$(TARGET_CFLAGS)" $(MAKE) -C $@

########
# minios
########

.PHONY: ioemu-stubdom
ioemu-stubdom: mini-os-ioemu lwip-cvs libxc ioemu
	DEF_CPPFLAGS="$(TARGET_CPPFLAGS)" DEF_CFLAGS="-DCONFIG_QEMU $(TARGET_CFLAGS)" DEF_LDFLAGS="$(TARGET_LDFLAGS)" $(MAKE) -C $(MINI_OS) OBJ_DIR=$(CURDIR)/$< LWIPDIR=$(CURDIR)/lwip-cvs APP_OBJS="$(CURDIR)/ioemu/i386-dm-stubdom/qemu.a $(CURDIR)/ioemu/i386-dm-stubdom/libqemu.a"

CAMLLIB = $(shell ocamlc -where)
.PHONY: caml-stubdom
caml-stubdom: mini-os-caml lwip-cvs libxc caml
	DEF_CPPFLAGS="$(TARGET_CPPFLAGS)" DEF_CFLAGS="-DCONFIG_CAML $(TARGET_CFLAGS)" DEF_LDFLAGS="$(TARGET_LDFLAGS)" $(MAKE) -C $(MINI_OS) OBJ_DIR=$(CURDIR)/$< LWIPDIR=$(CURDIR)/lwip-cvs APP_OBJS="$(CURDIR)/caml/main-caml.o $(CURDIR)/caml/caml.o $(CAMLLIB)/libasmrun.a"

.PHONY: c-stubdom
c-stubdom: mini-os-c lwip-cvs libxc c
	DEF_CPPFLAGS="$(TARGET_CPPFLAGS)" DEF_CFLAGS="-DCONFIG_C $(TARGET_CFLAGS)" DEF_LDFLAGS="$(TARGET_LDFLAGS)" $(MAKE) -C $(MINI_OS) OBJ_DIR=$(CURDIR)/$< LWIPDIR=$(CURDIR)/lwip-cvs APP_OBJS=$(CURDIR)/c/main.a

.PHONY: pv-grub
pv-grub: mini-os-grub libxc grub
	DEF_CPPFLAGS="$(TARGET_CPPFLAGS)" DEF_CFLAGS="-DCONFIG_GRUB $(TARGET_CFLAGS)" DEF_LDFLAGS="$(TARGET_LDFLAGS)" $(MAKE) -C $(MINI_OS) OBJ_DIR=$(CURDIR)/$< APP_OBJS=$(CURDIR)/grub/main.a

#########
# install
#########

install: install-ioemu install-grub

install-ioemu: mini-os-ioemu/mini-os.gz
	$(INSTALL_PROG) stubdom-dm "$(DESTDIR)/usr/lib/xen/bin"
	$(INSTALL_PROG) $< "$(DESTDIR)/usr/lib/xen/boot/ioemu-stubdom.gz"

install-grub: mini-os-grub/mini-os.gz
	$(INSTALL_PROG) $< "$(DESTDIR)/usr/lib/xen/boot/pv-grub.gz"

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
	rm -fr libxc ioemu mini-os include

# clean the cross-compilation result
.PHONY: crossclean
crossclean: clean
	rm -fr $(CROSS_ROOT)
	rm -fr newlib-build
	rm -fr zlib-$(ZLIB_VERSION) pciutils-$(LIBPCI_VERSION)

# clean patched sources
.PHONY: patchclean
patchclean: crossclean
	rm -fr newlib-cvs
	rm -fr lwip-cvs
	rm -fr grub-cvs

# clean downloads
.PHONY: downloadclean
downloadclean: patchclean
	rm -f zlib-$(ZLIB_VERSION).tar.gz
	rm -f pciutils-$(LIBPCI_VERSION).tar.bz2

.PHONY: distclean
distclean: downloadclean
