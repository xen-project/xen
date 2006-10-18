
include Config.mk

export DESTDIR

# Choose the best mirror to download linux kernel
KERNEL_REPO = http://www.kernel.org

ALLKERNELS = $(patsubst buildconfigs/mk.%,%,$(wildcard buildconfigs/mk.*))
ALLSPARSETREES = $(patsubst %-xen-sparse,%,$(wildcard *-xen-sparse))

# Setup pristine search path
PRISTINE_SRC_PATH	?= .:..
vpath pristine-% $(PRISTINE_SRC_PATH)

# Let XEN_TARGET_ARCH override ARCH.
ifeq ($(XEN_TARGET_ARCH),x86_32)
LINUX_ARCH	?= i386
else
LINUX_ARCH	?= $(XEN_TARGET_ARCH)
endif

# Expand Linux series to Linux version
LINUX_SERIES	?= 2.6
LINUX_VER	?= $(shell grep "^LINUX_VER " buildconfigs/mk.linux-2.6-xen | sed -e 's/.*=[ ]*//')

# Setup Linux search path
LINUX_SRC_PATH	?= .:..
vpath linux-%.tar.bz2 $(LINUX_SRC_PATH)
vpath patch-%.bz2 $(LINUX_SRC_PATH)

# download a pristine Linux kernel tarball if there isn't one in LINUX_SRC_PATH
linux-%.tar.bz2: override _LINUX_VDIR = $(word 1,$(subst ., ,$*)).$(word 2,$(subst ., ,$*))
linux-%.tar.bz2:
	@echo "Cannot find $@ in path $(LINUX_SRC_PATH)"
	wget $(KERNEL_REPO)/pub/linux/kernel/v$(_LINUX_VDIR)/$@ -O./$@

patch-%.bz2: override _LINUX_VDIR = $(word 1,$(subst ., ,$(*F))).$(word 2,$(subst ., ,$(*F)))
patch-%.bz2: override _LINUX_XDIR = $(if $(word 3,$(subst -, ,$(*F))),snapshots,testing)
patch-%.bz2:
	@echo "Cannot find $(@F) in path $(LINUX_SRC_PATH)"
	wget $(KERNEL_REPO)/pub/linux/kernel/v$(_LINUX_VDIR)/$(_LINUX_XDIR)/$(@F) -O./$@

pristine-%: pristine-%/.valid-pristine
	@true

pristine-%/.valid-pristine: %.tar.bz2
	rm -rf tmp-pristine-$* $(@D)
	mkdir -p tmp-pristine-$*
	tar -C tmp-pristine-$* -jxf $<
	-@rm -f tmp-pristine-$*/pax_global_header
	mv tmp-pristine-$*/* $(@D)
	@rm -rf tmp-pristine-$*
	touch $(@D)/.hgskip
	touch $@ # update timestamp to avoid rebuild

PATCHDIRS := $(wildcard patches/*-*)

ifneq ($(PATCHDIRS),)
-include $(patsubst %,%/.makedep,$(PATCHDIRS))

$(patsubst patches/%,patches/%/.makedep,$(PATCHDIRS)): patches/%/.makedep: 
	@echo 'ref-$*/.valid-ref: $$(wildcard patches/$*/*.patch)' >$@

ref-%/.valid-ref: pristine-%/.valid-pristine
	set -e
	rm -rf $(@D)
	cp -al $(<D) $(@D)
	if [ -d patches/$* ] ; then                                    \
	    echo Applying patches from patches/$*... ;                 \
	    for i in $$(cat patches/$*/series) ; do                    \
	        echo ... $$i ;                                         \
	        patch -d $(@D) -p1 --quiet <patches/$*/$$i || exit 1 ; \
	     done ;                                                    \
	fi
	touch $@ # update timestamp to avoid rebuild
endif

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

linux-2.6-xen.patch: ref-linux-$(LINUX_VER)/.valid-ref
	rm -rf tmp-$@
	cp -al $(<D) tmp-$@
	( cd linux-2.6-xen-sparse && bash ./mkbuildtree ../tmp-$@ )	
	diff -Nurp $(patsubst ref%,pristine%,$(<D)) tmp-$@ > $@ || true
	rm -rf tmp-$@

%-xen.patch: ref-%/.valid-ref
	rm -rf tmp-$@
	cp -al $(<D) tmp-$@
	( cd $*-xen-sparse && bash ./mkbuildtree ../tmp-$@ )	
	diff -Nurp $(patsubst ref%,pristine%,$(<D)) tmp-$@ > $@ || true
	rm -rf tmp-$@

%-mrproper:
	$(MAKE) -f buildconfigs/mk.$*-xen mrpropper
	rm -rf pristine-$(*)* ref-$(*)*
	rm -rf $*-xen.patch

.PHONY: config-update-pae
config-update-pae:
ifeq ($(XEN_TARGET_X86_PAE),y)
	sed -e 's!^CONFIG_HIGHMEM4G=y$$!\# CONFIG_HIGHMEM4G is not set!;s!^\# CONFIG_HIGHMEM64G is not set$$!CONFIG_HIGHMEM64G=y!' $(CONFIG_FILE) > $(CONFIG_FILE)- && mv $(CONFIG_FILE)- $(CONFIG_FILE)
else
	grep '^CONFIG_HIGHMEM64G=y' $(CONFIG_FILE) >/dev/null && ( sed -e 's!^CONFIG_HIGHMEM64G=y$$!\# CONFIG_HIGHMEM64G is not set!;s!^\# CONFIG_HIGHMEM4G is not set$$!CONFIG_HIGHMEM4G=y!' $(CONFIG_FILE) > $(CONFIG_FILE)- && mv $(CONFIG_FILE)- $(CONFIG_FILE) ) || true
endif

# never delete any intermediate files.
.SECONDARY:
