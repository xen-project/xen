
override XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk
include Config

D=gpxe
T=gpxe-git-snapshot.tar.gz

ROMS = $(addprefix $D/src/bin/, $(addsuffix .rom, $(NICS)))

.PHONY: all
all: eb-roms.h

%.rom: $D/src/arch/i386/Config
	$(MAKE) -C $D/src bin/$(*F).rom

eb-roms.h.new: $(ROMS)
	cat $^ | ../hvmloader/mkhex etherboot >$@

eb-roms.h: Config
	$(MAKE) NO_WERROR=1 $@.new
	mv -f $@.new $@

$D/src/arch/i386/Config: $T Config
	rm -rf $D
	gzip -dc $T | tar xf -
	for i in $$(cat patches/series) ; do                 \
	    patch -d $D -p1 --quiet <patches/$$i || exit 1 ; \
	done
	cat Config >>$@

$D/src/bin/NIC: $D/src/arch/i386/Config
	$(MAKE) -C $D/src bin/NIC

.PHONY: clean
clean:
	rm -rf $D *~ eb-roms.h
