XEN_ROOT = ..
MINI_OS = $(XEN_ROOT)/extras/mini-os

export XEN_OS=MiniOS

include $(XEN_ROOT)/Config.mk
export stubdom=y
export debug=y

IOEMU_OPTIONS=--disable-vnc-tls 
BINUTILS_VERSION=2.18
GCC_VERSION=4.2.2
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
export CROSS_COMPILE=$(GNU_TARGET_ARCH)-xen-elf-
export PATH:=$(CROSS_PREFIX)/bin:$(PATH)

TARGETS=ioemu c caml grub

.PHONY: all
all: ioemu-stubdom c-stubdom pv-grub

################
# Cross-binutils
################

binutils-$(BINUTILS_VERSION).tar.bz2:
	$(WGET) http://ftp.gnu.org/gnu/binutils/$@
binutils-$(BINUTILS_VERSION): binutils-$(BINUTILS_VERSION).tar.bz2
	tar xjf $<
	patch -d $@ -p1 < binutils.patch
	touch $@

BINUTILS_STAMPFILE=$(CROSS_ROOT)/bin/$(GNU_TARGET_ARCH)-xen-elf-ar
.PHONY: cross-binutils
cross-binutils: $(BINUTILS_STAMPFILE)
$(BINUTILS_STAMPFILE): binutils-$(BINUTILS_VERSION)
	mkdir -p binutils-build
	( cd binutils-build && \
	  ../binutils-$(BINUTILS_VERSION)/configure --prefix=$(CROSS_PREFIX) --verbose --target=$(GNU_TARGET_ARCH)-xen-elf && \
	  $(MAKE) && \
	  $(MAKE) check && \
	  $(MAKE) install )

###########
# Cross-gcc
###########

gcc-$(GCC_VERSION).tar.bz2:
	$(WGET) http://ftp.gnu.org/gnu/gcc/gcc-$(GCC_VERSION)/gcc-$(GCC_VERSION).tar.bz2
gcc-$(GCC_VERSION): gcc-$(GCC_VERSION).tar.bz2
	tar xjf $<
	patch -d $@ -p1 < gcc.patch
	touch $@

GCC_STAMPFILE=$(CROSS_ROOT)/bin/$(GNU_TARGET_ARCH)-xen-elf-gcc-$(GCC_VERSION)
.PHONY: cross-gcc
cross-gcc: $(GCC_STAMPFILE)
$(GCC_STAMPFILE): gcc-$(GCC_VERSION) $(BINUTILS_STAMPFILE)
	mkdir -p gcc-build
	( cd gcc-build && \
	  ../gcc-$(GCC_VERSION)/configure --prefix=$(CROSS_PREFIX) --verbose --target=$(GNU_TARGET_ARCH)-xen-elf --enable-languages=c --disable-libssp --with-gnu-as --with-gnu-ld && \
	  $(MAKE) GCC_FOR_TARGET='$$$$r/gcc/xgcc -B$$$$r/gcc/ '"$(TARGET_CFLAGS)"' $$(FLAGS_FOR_TARGET)' && \
	  $(MAKE) install )

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
$(NEWLIB_STAMPFILE): newlib-cvs $(GCC_STAMPFILE)
	mkdir -p newlib-build
	( cd newlib-build && \
	  CC_FOR_TARGET="$(GNU_TARGET_ARCH)-xen-elf-gcc $(TARGET_CFLAGS) $(NEWLIB_CFLAGS)" ../newlib-cvs/configure --prefix=$(CROSS_PREFIX) --verbose --target=$(GNU_TARGET_ARCH)-xen-elf --enable-newlib-io-long-long && \
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
	  CFLAGS="$(TARGET_CFLAGS)" CC=$(GNU_TARGET_ARCH)-xen-elf-gcc ./configure --prefix=$(CROSS_PREFIX)/$(GNU_TARGET_ARCH)-xen-elf && \
	  $(MAKE) libz.a && \
	  $(MAKE) install )

##############
# Cross-libpci
##############

pciutils-$(LIBPCI_VERSION).tar.bz2:
	$(WGET) http://www.kernel.org/pub/software/utils/pciutils/pciutils-$(LIBPCI_VERSION).tar.bz2

LIBPCI_STAMPFILE=$(CROSS_ROOT)/$(GNU_TARGET_ARCH)-xen-elf/lib/libpci.a
.PHONY: cross-libpci
cross-libpci: $(LIBPCI_STAMPFILE)
$(LIBPCI_STAMPFILE): pciutils-$(LIBPCI_VERSION).tar.bz2 $(NEWLIB_STAMPFILE) $(ZLIB_STAMPFILE)
	tar xjf $<
	( cd pciutils-$(LIBPCI_VERSION) && \
	  cp ../libpci.config.h lib/config.h && \
	  echo '#define PCILIB_VERSION "$(LIBPCI_VERSION)"' >> lib/config.h && \
	  cp ../libpci.config.mak lib/config.mk && \
	  $(MAKE) CC="$(GNU_TARGET_ARCH)-xen-elf-gcc $(TARGET_CFLAGS)" lib/libpci.a && \
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
libxc/libxenctrl.a libxc/libxenguest.a: cross-zlib mk-symlinks
	$(MAKE) -C libxc

#######
# ioemu
#######

.PHONY: ioemu
ioemu: cross-zlib cross-libpci mk-symlinks libxc
	[ -f ioemu/config-host.mak ] || \
	  ( cd ioemu ; XEN_TARGET_ARCH=$(XEN_TARGET_ARCH) sh configure --prefix=/usr --enable-stubdom $(IOEMU_OPTIONS))
	$(MAKE) -C ioemu LWIPDIR=$(CURDIR)/lwip-cvs

######
# caml
######

.PHONY: caml
caml: cross-newlib mk-symlinks
	$(MAKE) -C $@ LWIPDIR=$(CURDIR)/lwip-cvs 

###
# C
###

.PHONY: c
c: cross-newlib mk-symlinks
	$(MAKE) -C $@ LWIPDIR=$(CURDIR)/lwip-cvs 

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
	$(MAKE) -C $@

########
# minios
########

.PHONY: ioemu-stubdom
ioemu-stubdom: mini-os-ioemu lwip-cvs libxc ioemu
	DEF_CFLAGS=-DCONFIG_QEMU $(MAKE) -C $(MINI_OS) OBJ_DIR=$(CURDIR)/$< LWIPDIR=$(CURDIR)/lwip-cvs APP_OBJS="$(CURDIR)/ioemu/i386-dm-stubdom/qemu.a $(CURDIR)/ioemu/i386-dm-stubdom/libqemu.a"

CAMLLIB = $(shell ocamlc -where)
.PHONY: caml-stubdom
caml-stubdom: mini-os-caml lwip-cvs libxc caml
	DEF_CFLAGS=-DCONFIG_CAML $(MAKE) -C $(MINI_OS) OBJ_DIR=$(CURDIR)/$< LWIPDIR=$(CURDIR)/lwip-cvs APP_OBJS="$(CURDIR)/caml/main-caml.o $(CURDIR)/caml/caml.o $(CAMLLIB)/libasmrun.a"

.PHONY: c-stubdom
c-stubdom: mini-os-c lwip-cvs libxc c
	DEF_CFLAGS=-DCONFIG_C $(MAKE) -C $(MINI_OS) OBJ_DIR=$(CURDIR)/$< LWIPDIR=$(CURDIR)/lwip-cvs APP_OBJS=$(CURDIR)/c/main.a

.PHONY: pv-grub
pv-grub: mini-os-grub libxc grub
	DEF_CFLAGS=-DCONFIG_GRUB $(MAKE) -C $(MINI_OS) OBJ_DIR=$(CURDIR)/$< APP_OBJS=$(CURDIR)/grub/main.a

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
	rm -fr binutils-build gcc-build newlib-build
	rm -fr zlib-$(ZLIB_VERSION) pciutils-$(LIBPCI_VERSION)

# clean patched sources
.PHONY: patchclean
patchclean: crossclean
	rm -fr binutils-$(BINUTILS_VERSION)
	rm -fr gcc-$(GCC_VERSION)
	rm -fr newlib-cvs
	rm -fr lwip-cvs
	rm -fr grub-cvs

# clean downloads
.PHONY: downloadclean
downloadclean: patchclean
	rm -f binutils-$(BINUTILS_VERSION).tar.bz2
	rm -f gcc-$(GCC_VERSION).tar.bz2
	rm -f zlib-$(ZLIB_VERSION).tar.gz
	rm -f pciutils-$(LIBPCI_VERSION).tar.bz2

.PHONY: distclean
distclean: downloadclean
