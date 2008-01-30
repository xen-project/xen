
EB_VERSION=5.4.2

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
	./find-gcc-3 >>$D/src/Config
	mv $D $E

clean:
	rm -rf $D $E *.zrom.h *~

.PHONY: all clean
