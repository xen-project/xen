
XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/Config.mk
-include $(XEN_ROOT)/config/Docs.mk

TARGETS= network-bridge.png network-basic.png

all: $(TARGETS)

%.png:	%.fig
	$(FIG2DEV) -L png $< >$@.tmp
	mv -f $@.tmp $@

clean:
	rm -f *~ *.png
