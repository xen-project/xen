
# We expect these two to already be set if people 
# are using the top-level Makefile
DISTDIR	?= $(CURDIR)/dist
DESTDIR	?= $(DISTDIR)/install

ALLKERNELS = $(patsubst buildconfigs/mk.%,%,$(wildcard buildconfigs/mk.*))
ALLSPARSETREES = $(patsubst %-xen-sparse,%,$(wildcard *-xen-sparse))

.PHONY:	mkpatches mrproper

# Setup pristine search path
PRISTINE_SRC_PATH	?= .:..
vpath pristine-% $(PRISTINE_SRC_PATH)

# Expand Linux series to Linux version
LINUX_SERIES	?= 2.6
LINUX_VER	?= $(patsubst linux-%-xen-sparse,%,$(wildcard linux-$(LINUX_SERIES)*-xen-sparse))

# Setup Linux search path
LINUX_SRC_PATH	?= .:..
vpath linux-%.tar.bz2 $(LINUX_SRC_PATH)

# download a pristine Linux kernel tarball if there isn't one in LINUX_SRC_PATH
linux-%.tar.bz2: override _LINUX_VDIR = $(word 1,$(subst ., ,$*)).$(word 2,$(subst ., ,$*))
linux-%.tar.bz2:
	@echo "Cannot find $@ in path $(LINUX_SRC_PATH)"
	wget http://www.kernel.org/pub/linux/kernel/v$(_LINUX_VDIR)/$@ -O./$@

# Expand NetBSD release to NetBSD version
NETBSD_RELEASE  ?= 2.0
NETBSD_VER      ?= $(patsubst netbsd-%-xen-sparse,%,$(wildcard netbsd-$(NETBSD_RELEASE)*-xen-sparse))
NETBSD_CVSSNAP  ?= 20050309

# Setup NetBSD search path
NETBSD_SRC_PATH	?= .:..
vpath netbsd-%.tar.bz2 $(NETBSD_SRC_PATH)

# download a pristine NetBSD tarball if there isn't one in NETBSD_SRC_PATH
netbsd-%-xen-kernel-$(NETBSD_CVSSNAP).tar.bz2:
	@echo "Cannot find $@ in path $(NETBSD_SRC_PATH)"
	wget http://www.cl.cam.ac.uk/Research/SRG/netos/xen/downloads/$@ -O./$@

netbsd-%.tar.bz2: netbsd-%-xen-kernel-$(NETBSD_CVSSNAP).tar.bz2
	ln -fs $< $@

ifeq ($(OS),linux)
OS_VER = $(LINUX_VER)
else
OS_VER = $(NETBSD_VER)
endif

$(patsubst %,pristine-%/.valid-pristine,$(ALLSPARSETREES)) : pristine-%/.valid-pristine: %.tar.bz2
	rm -rf tmp-pristine-$* $(@D)
	mkdir -p tmp-pristine-$*
	tar -C tmp-pristine-$* -jxf $<
	mv tmp-pristine-$*/* $(@D)
	@rm -rf tmp-pristine-$*
	touch $@ # update timestamp to avoid rebuild

PATCHDIRS := $(wildcard patches/*-*)

-include $(patsubst %,%/.makedep,$(PATCHDIRS))

$(patsubst patches/%,patches/%/.makedep,$(PATCHDIRS)): patches/%/.makedep: 
	@echo 'ref-$*/.valid-ref: $$(wildcard patches/$*/*.patch)' >$@

clean::
	rm -f patches/*/.makedep

ref-%/.valid-ref: pristine-%/.valid-pristine
	rm -rf $(@D)
	cp -al $(<D) $(@D)
	[ -d patches/$* ] && \
	  for i in patches/$*/*.patch ; do ( cd $(@D) ; patch -p1 <../$$i || exit 1 ) ; done
	touch $@ # update timestamp to avoid rebuild

%-build:
	$(MAKE) -f buildconfigs/mk.$* build

%-delete:
	$(MAKE) -f buildconfigs/mk.$* delete

%-clean:
	$(MAKE) -f buildconfigs/mk.$* clean

%-xen.patch: ref-%/.valid-ref
	rm -rf tmp-$@
	cp -al $(<D) tmp-$@
	( cd $*-xen-sparse && ./mkbuildtree ../tmp-$@ )	
	diff -Nurp $(<D) tmp-$@ > $@ || true
	rm -rf tmp-$@

%-mrproper: %-mrproper-extra
	rm -rf pristine-$* ref-$* $*.tar.bz2
	rm -rf $*-xen.patch

netbsd-%-mrproper-extra:
	rm -rf netbsd-$*-tools netbsd-$*-tools.tar.bz2
	rm -f netbsd-$*-xen-kernel-$(NETBSD_CVSSNAP).tar.bz2

%-mrproper-extra:
	@: # do nothing

# never delete any intermediate files.
.SECONDARY:
