
EB_VERSION=5.4.2

override XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

D=etherboot-$(EB_VERSION)
T=etherboot-$(EB_VERSION).tar.gz
E=etherboot-build

TARGETS=eb-rtl8139.zrom.h

all: $(TARGETS)

eb-%.zrom.h: $E/src/Config
	$(MAKE) -C $E/src bin/$*.zrom
	../hvmloader/mkhex etherboot <$E/src/bin/$*.zrom >$@.new
	mv -f $@.new $@

$E/src/Config:	$T Config
	rm -rf $D $E
	tar zxf $T
	cat Config >>$D/src/Config
	@
	# override many of the settings in Config
	echo ARCH=i386 >>$D/src/Config
	echo "HOST_CC=$(HOSTCC)" >>$D/src/Config
	echo "CPP=$(CPP)" >>$D/src/Config
	echo "CC=$(CC)" >>$D/src/Config
	echo "AS=$(CC) -c -x assembler -" >>$D/src/Config
	echo "LD=$(LD)" >>$D/src/Config
	echo "SIZE=$(SIZE)" >>$D/src/Config
	echo "AR=$(AR)" >>$D/src/Config
	echo "RANLIB=$(RANLIB)" >>$D/src/Config
	echo "OBJCOPY=$(OBJCOPY)" >>$D/src/Config
	echo "CFLAGS+=$(CFLAGS)" >>$D/src/Config
	echo "ASFLAGS+=$(CFLAGS)" >>$D/src/Config
	echo "LDFLAGS+=$(LDFLAGS_DIRECT)" >>$D/src/Config
	@
	set -e; cd $D/src/arch/i386; \
		sed -e '/ifneq.*GCC_MINORVERSION/,/endif/ s/^/#/' \
			Config >Config.new; \
		mv Config.new Config
	mv $D $E

clean:
	rm -rf $D $E *.zrom.h *~

.PHONY: all clean
