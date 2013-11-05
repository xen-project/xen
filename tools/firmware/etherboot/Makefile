
override XEN_TARGET_ARCH = x86_32
XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk
include Config

ifeq ($(GIT_HTTP),y)
IPXE_GIT_URL ?= http://git.ipxe.org/ipxe.git
else
IPXE_GIT_URL ?= git://git.ipxe.org/ipxe.git
endif

IPXE_GIT_TAG := 9a93db3f0947484e30e753bbd61a10b17336e20e

IPXE_TARBALL_URL ?= $(XEN_EXTFILES_URL)/ipxe-git-$(IPXE_GIT_TAG).tar.gz

D=ipxe
T=ipxe.tar.gz

ROMS = $(addprefix $D/src/bin/, $(addsuffix .rom, $(ETHERBOOT_NICS)))

.NOTPARALLEL:

.PHONY: all
all: $(ROMS)

%.rom: $D/src/arch/i386/Makefile
	$(MAKE) -C $D/src bin/$(*F).rom

$T:
	if ! $(FETCHER) _$T $(IPXE_TARBALL_URL); then \
		$(GIT) clone $(IPXE_GIT_URL) $D.git; \
		(cd $D.git && $(GIT) archive --format=tar --prefix=$D/ \
		$(IPXE_GIT_TAG) | gzip >../_$T); \
		rm -rf $D.git; \
	fi
	mv _$T $T

$D/src/arch/i386/Makefile: $T Config
	rm -rf $D
	gzip -dc $T | tar xf -
	for i in $$(cat patches/series) ; do                 \
	    patch -d $D -p1 --quiet <patches/$$i || exit 1 ; \
	done
	cat Config >>$@

$D/src/bin/NIC: $D/src/arch/i386/Makefile
	$(MAKE) -C $D/src bin/NIC

.PHONY: clean
clean:
	rm -rf $D $D.git *~ _$T $T

.PHONY: distclean
distclean: clean
	rm -rf $T
