
include Config.mk

export DESTDIR

ALLKERNELS = $(patsubst buildconfigs/mk.%,%,$(wildcard buildconfigs/mk.*))

%-install:
	$(MAKE) -f buildconfigs/mk.$* build

%-dist: DESTDIR=$(DISTDIR)/install
%-dist: %-install
	@: # do nothing

# Legacy dist target
%-build: %-dist
	@: # do nothing

%-prep: DESTDIR=$(DISTDIR)/install
%-prep:
	$(MAKE) -f buildconfigs/mk.$* prep

%-config: DESTDIR=$(DISTDIR)/install
%-config:
	$(MAKE) -f buildconfigs/mk.$* config

%-delete:
	$(MAKE) -f buildconfigs/mk.$* delete

%-clean:
	$(MAKE) -f buildconfigs/mk.$* clean

%.patch:
	$(MAKE) -f buildconfigs/mk.$* $@

%-mrproper:
	$(MAKE) -f buildconfigs/mk.$*-xen mrproper
	rm -rf pristine-$(*)* ref-$(*)*
	rm -rf $*-xen.patch

# never delete any intermediate files.
.SECONDARY:
