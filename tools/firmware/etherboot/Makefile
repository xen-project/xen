
override XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk
include Config

ifeq ($(GIT_HTTP),y)
GPXE_GIT_URL := http://git.etherboot.org/scm/gpxe.git
else
GPXE_GIT_URL := git://git.etherboot.org/scm/gpxe.git
endif

GPXE_GIT_TAG := v1.0.1

D=gpxe
T=gpxe-git-snapshot.tar.gz

ROMS = $(addprefix $D/src/bin/, $(addsuffix .rom, $(NICS)))

.NOTPARALLEL:

.PHONY: all
all: eb-roms.h

%.rom: $D/src/arch/i386/Makefile
	$(MAKE) -C $D/src bin/$(*F).rom

eb-roms.h.new: $(ROMS)
	cat $^ | ../hvmloader/mkhex etherboot >$@

eb-roms.h: Config
	$(MAKE) NO_WERROR=1 $@.new
	mv -f $@.new $@

$T:
	$(GIT) clone $(GPXE_GIT_URL) $D.git
	cd $D.git && \
	$(GIT) archive --format=tar --prefix=$D/ $(GPXE_GIT_TAG) | gzip >../$T
	rm -rf $D.git

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
	rm -rf $D $D.git *~ eb-roms.h

.PHONY: distclean
distclean: clean
	rm -rf $T
