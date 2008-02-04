
EB_VERSION=5.4.2

override XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk
include Config

D=etherboot-$(EB_VERSION)
T=etherboot-$(EB_VERSION).tar.gz
E=etherboot-build

ROM_ZHS = $(addprefix eb-, $(addsuffix .zrom.h, $(NICS)))

.PHONY: all
all: eb-roms.h

eb-%.zrom.h: $E/src/Config
	$(MAKE) -C $E/src bin/$*.zrom
	../hvmloader/mkhex etherboot_$* <$E/src/bin/$*.zrom >$@.new
	mv -f $@.new $@

eb-rom-list.h: make-eb-rom-list $E/src/bin/Roms
	./$^ $(NICS) >$@.new && mv -f $@.new $@

eb-roms.h.new: eb-rom-list.h $(ROM_ZHS)
	cat $^ >$@

eb-roms.h: Config
	$(MAKE) $@.new
	mv -f $@.new $@

$E/src/Config: $T Config
	rm -rf $D $E
	gzip -dc $T | tar xf -
	cat Config >>$D/src/Config
	@
	# override many of the settings in Config
	echo ARCH=i386 >>$D/src/Config
	echo "HOST_CC=$(HOSTCC)" >>$D/src/Config
	echo "CPP=$(CPP)" >>$D/src/Config
	echo "CC=$(CC)" >>$D/src/Config
	echo "AS=$(AS)" >>$D/src/Config
	echo "LD=$(LD)" >>$D/src/Config
	echo "SIZE=$(SIZE)" >>$D/src/Config
	echo "AR=$(AR)" >>$D/src/Config
	echo "RANLIB=$(RANLIB)" >>$D/src/Config
	echo "OBJCOPY=$(OBJCOPY)" >>$D/src/Config
	echo "CFLAGS+=$(CFLAGS)" >>$D/src/Config
	echo "ASFLAGS+=$(ASFLAGS)" >>$D/src/Config
	echo "LDFLAGS+=$(LDFLAGS_DIRECT)" >>$D/src/Config
	@
	set -e; cd $D/src/arch/i386; \
		sed -e '/ifneq.*GCC_MINORVERSION/,/endif/ s/^/#/' \
			Config >Config.new; \
		mv Config.new Config
	mv $D $E

$E/src/bin/Roms: $E/src/Config
	$(MAKE) -C $E/src bin/Roms

.PHONY: clean
clean:
	rm -rf $D $E *.zrom.h eb-rom-list.h *~
