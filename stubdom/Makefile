XEN_ROOT = ..

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
LWIP_DATE=2008-02-08

WGET=wget -c

GNU_TARGET_ARCH:=$(XEN_TARGET_ARCH)
ifeq ($(XEN_TARGET_ARCH),x86_32)
GNU_TARGET_ARCH:=i686
endif

ifeq ($(GNU_TARGET_ARCH), i686)
TARGET_CFLAGS=
endif
ifeq ($(GNU_TARGET_ARCH), x86_64)
TARGET_CFLAGS=-mno-red-zone
endif
ifeq ($(GNU_TARGET_ARCH), ia64)
TARGET_CFLAGS=-mconstant-gp
endif

CROSS_ROOT=cross-root-$(GNU_TARGET_ARCH)
CROSS_PREFIX=$(CURDIR)/$(CROSS_ROOT)
export CROSS_COMPILE=$(GNU_TARGET_ARCH)-xen-elf-
export PATH:=$(CROSS_PREFIX)/bin:$(PATH)

.PHONY: all
all: qemu-stubdom

################
# Cross-binutils
################

binutils-$(BINUTILS_VERSION).tar.bz2:
	$(WGET) http://ftp.gnu.org/gnu/binutils/$@
binutils-$(BINUTILS_VERSION): binutils-$(BINUTILS_VERSION).tar.bz2
	tar xjf $@.tar.bz2
	( cd binutils-$(BINUTILS_VERSION) && patch -p1 < ../binutils.patch )
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
	tar xjf gcc-$(GCC_VERSION).tar.bz2
	( cd gcc-$(GCC_VERSION) && patch -p1 < ../gcc.patch )
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
	( cd newlib-cvs && patch -p0 < ../newlib.patch)

NEWLIB_STAMPFILE=$(CROSS_ROOT)/$(GNU_TARGET_ARCH)-xen-elf/lib/libc.a
.PHONY: cross-newlib
cross-newlib: $(NEWLIB_STAMPFILE)
$(NEWLIB_STAMPFILE): newlib-cvs $(GCC_STAMPFILE)
	mkdir -p newlib-build
	( cd newlib-build && \
	  CC_FOR_TARGET="$(GNU_TARGET_ARCH)-xen-elf-gcc $(TARGET_CFLAGS)" ../newlib-cvs/configure --prefix=$(CROSS_PREFIX) --verbose --target=$(GNU_TARGET_ARCH)-xen-elf --enable-newlib-io-long-long && \
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
	cvs -z 9 -d :pserver:anonymous@cvs.savannah.nongnu.org:/sources/lwip co -D $(LWIP_DATE) lwip
	mv lwip lwip-cvs

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
	  ln -sf ../../tools/libxc/*.h . && \
	  ln -sf ../../tools/libxc/*.c . && \
	  ln -sf ../../tools/libxc/Makefile . )
	mkdir -p libxc/$(XEN_TARGET_ARCH)
	[ -h libxc/$(XEN_TARGET_ARCH) ] || ( cd libxc/$(XEN_TARGET_ARCH) && \
	  ln -sf ../../tools/libxc/$(XEN_TARGET_ARCH)/*.c . && \
	  ln -sf ../../tools/libxc/$(XEN_TARGET_ARCH)/*.h . && \
	  ln -sf ../../tools/libxc/$(XEN_TARGET_ARCH)/Makefile . )
	mkdir -p ioemu
	[ -h ioemu/Makefile ] || ( cd ioemu && \
	  ln -sf ../../tools/ioemu/* . && \
	  ([ ! -h config-host.h ] || rm -f config-host.h) && \
	  ([ ! -h config-host.mak ] || rm -f config-host.mak) )
	[ -h mini-os ] || ln -sf ../extras/mini-os .

#######
# libxc
#######

.PHONY: libxc
libxc: cross-zlib mk-symlinks
	$(MAKE) -C $@

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
caml:
	$(MAKE) -C $@

########
# minios
########

.PHONY: qemu-stubdom
qemu-stubdom: mk-symlinks lwip-cvs libxc ioemu
	$(MAKE) -C mini-os LWIPDIR=$(CURDIR)/lwip-cvs QEMUDIR=$(CURDIR)/ioemu

.PHONY: caml-stubdom
caml-stubdom: mk-symlinks lwip-cvs libxc cross-libpci caml
	$(MAKE) -C mini-os LWIPDIR=$(CURDIR)/lwia-cvs CAMLDIR=$(CURDIR)/caml

#########
# install
#########

install: mini-os/mini-os.gz
	$(INSTALL_PROG) stubdom-dm "$(DESTDIR)/usr/lib/xen/bin"
	$(INSTALL_PROG) mini-os/mini-os.gz "$(DESTDIR)/usr/lib/xen/boot/stubdom.gz"

#######
# clean
#######

# Only clean the libxc/ioemu/mini-os part
.PHONY: clean
clean:
	-$(MAKE) -C mini-os LWIPDIR=$(CURDIR)/lwip-cvs clean
	$(MAKE) -C caml clean
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

# clean downloads
.PHONY: downloadclean
downloadclean: patchclean
	rm -f binutils-$(BINUTILS_VERSION).tar.bz2
	rm -f gcc-$(GCC_VERSION).tar.bz2
	rm -f zlib-$(ZLIB_VERSION).tar.gz
	rm -f pciutils-$(LIBPCI_VERSION).tar.bz2

.PHONY: distclean
distclean: downloadclean
