
# We expect these two to already be set if people 
# are using the top-level Makefile
DIST_DIR	?= $(shell pwd)/dist
INSTALL_DIR	?= $(DIST_DIR)/install

.PHONY:	mkpatches mrproper



# Expand Linux series to Linux version
LINUX_SERIES	?= 2.6
LINUX_VER	?= $(patsubst linux-%-xen-sparse,%,$(wildcard linux-$(LINUX_SERIES)*-xen-sparse))

# Setup Linux search patch
LINUX_SRC_PATH	?= .:..
vpath linux-%.tar.bz2 $(LINUX_SRC_PATH)

# download a pristine Linux kernel tarball if there isn't one in LINUX_SRC_PATH
linux-%.tar.bz2: override _LINUX_VDIR = $(word 1,$(subst ., ,$*)).$(word 2,$(subst ., ,$*))
linux-%.tar.bz2:
	@echo "Cannot find linux-$*.tar.bz2 in path $(LINUX_SRC_PATH)"
	wget http://www.kernel.org/pub/linux/kernel/v$(_LINUX_VDIR)/linux-$*.tar.bz2 -O./$@



# Expand NetBSD release to NetBSD version
NETBSD_RELEASE  ?= 2.0
NETBSD_VER      ?= $(patsubst netbsd-%-xen-sparse,%,$(wildcard netbsd-$(NETBSD_RELEASE)*-xen-sparse))
NETBSD_CVSSNAP  ?= 20041103

# Setup NetBSD search patch
NETBSD_SRC_PATH	?= .:..
vpath netbsd-%.tar.bz2 $(NETBSD_SRC_PATH)

# download a pristine NetBSD tarball if there isn't one in NETBSD_SRC_PATH
netbsd-%-xen-kernel-$(NETBSD_CVSSNAP).tar.bz2:
	@echo "Cannot find $@ in path $(NETBSD_SRC_PATH)"
	wget http://www.cl.cam.ac.uk/Research/SRG/netos/xen/downloads/netbsd-$(NETBSD_VER)-xen-kernel-$(NETBSD_CVSSNAP).tar.bz2 -O./$@

netbsd-%.tar.bz2: netbsd-%-xen-kernel-$(NETBSD_CVSSNAP).tar.bz2
	ln -fs $< $@




pristine-%: %.tar.bz2
	rm -rf tmp-$* $@ && \
	  mkdir -p tmp-$* && \
	  tar -C tmp-$* -jxf $< && \
	  mv tmp-$*/* $@
	touch $@ # update timestamp to avoid rebuild
	@rm -rf tmp-$*

%-xen.patch: pristine-%
	rm -rf tmp-$@
	cp -al pristine-$* tmp-$@
	( cd $*-xen-sparse && ./mkbuildtree ../tmp-$@ )	
	diff -Nurp pristine-$* tmp-$@ > $@ || true
	rm -rf tmp-$@

%-mrproper: %-mrproper-extra
	rm -rf pristine-$* $*.tar.bz2
	rm -rf $*-xen.patch

netbsd-%-mrproper-extra:
	rm -rf netbsd-$*-tools netbsd-$*-tools.tar.bz2
	rm -f netbsd-$*-xen-kernel-$(NETBSD_CVSSNAP).tar.bz2

%-mrproper-extra:
	@: # do nothing

# never delete any intermediate files.
.SECONDARY:
