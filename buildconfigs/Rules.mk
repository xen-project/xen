
# We expect these two to already be set if people 
# are using the top-level Makefile
DIST_DIR    ?= $(shell pwd)/dist
INSTALL_DIR ?= $(DIST_DIR)/install


# Figure out which Linux version
LINUX_26VER ?= $(shell ( /bin/ls -ld linux-2.6.*-xen-sparse ) \
		2>/dev/null | sed -e 's!^.*linux-\(.\+\)-xen-sparse!\1!' )

LINUX_24VER ?= $(shell ( /bin/ls -ld linux-2.4.*-xen-sparse ) \
		2>/dev/null | sed -e 's!^.*linux-\(.\+\)-xen-sparse!\1!' )

LINUX_SRC_PATH   ?= .:..

LINUX_26SRC      ?= $(firstword $(foreach dir,$(subst :, ,$(LINUX_SRC_PATH)),\
                    $(wildcard $(dir)/linux-$(LINUX_26VER).tar.*z*)))

LINUX_24SRC      ?= $(firstword $(foreach dir,$(subst :, ,$(LINUX_SRC_PATH)),\
                    $(wildcard $(dir)/linux-$(LINUX_24VER).tar.*z*)))

.PHONY:	mkpatches linux-$(LINUX_24VER)-xen.patch linux-$(LINUX_26VER)-xen.patch mrproper

# search for a pristine kernel tar ball, or try downloading one
linux-$(LINUX_26VER).tar.bz2:
ifeq ($(LINUX_26SRC),)
	echo "Cannot find linux-$(LINUX_26VER).tar.bz2 in path $(LINUX_SRC_PATH)"
	wget http://www.kernel.org/pub/linux/kernel/v2.6/linux-$(LINUX_26VER).tar.bz2 -O./linux-$(LINUX_26VER).tar.bz2
LINUX_26SRC := ./linux-$(LINUX_26VER).tar.bz2 
endif

pristine-linux-$(LINUX_26VER): $(LINUX_26SRC)
	rm -rf tmp-linux-$(LINUX_26VER) $@ && mkdir -p tmp-linux-$(LINUX_26VER) && tar -C tmp-linux-$(LINUX_26VER) -jxf $(LINUX_26SRC) && mv tmp-linux-$(LINUX_26VER)/* $@ ; rm -rf tmp-linux-$(LINUX_26VER)
	touch $@ # update timestamp to avoid rebuild


# search for a pristine kernel tar ball, or try downloading one
linux-$(LINUX_24VER).tar.bz2:
ifeq ($(LINUX_24SRC),)
	echo "Cannot find linux-$(LINUX_24VER).tar.bz2 in path $(LINUX_SRC_PATH)"
	wget http://www.kernel.org/pub/linux/kernel/v2.4/linux-$(LINUX_24VER).tar.bz2 -O./linux-$(LINUX_24VER).tar.bz2
LINUX_24SRC := ./linux-$(LINUX_24VER).tar.bz2 
endif

pristine-linux-$(LINUX_24VER): $(LINUX_24SRC)
	rm -rf tmp-linux-$(LINUX_24VER) $@ && mkdir -p tmp-linux-$(LINUX_24VER) && tar -C tmp-linux-$(LINUX_24VER) -jxf $(LINUX_24SRC) && mv tmp-linux-$(LINUX_24VER)/* $@ ; rm -rf tmp-linux-$(LINUX_24VER)
	touch $@ # update timestamp to avoid rebuild

linux-$(LINUX_24VER)-xen.patch: pristine-linux-$(LINUX_24VER)	
	rm -rf tmp-$@
	cp -al pristine-linux-$(LINUX_24VER) tmp-$@
	( cd linux-$(LINUX_24VER)-xen-sparse ; \
          ./mkbuildtree ../tmp-$@ )	
	diff -Nurp pristine-linux-$(LINUX_24VER) tmp-$@ > $@ || true
	rm -rf tmp-$@

linux-$(LINUX_26VER)-xen.patch: pristine-linux-$(LINUX_26VER)
	rm -rf tmp-$@
	cp -al pristine-linux-$(LINUX_26VER) tmp-$@
	( cd linux-$(LINUX_26VER)-xen-sparse ; \
          ./mkbuildtree ../tmp-$@ )	
	diff -Nurp pristine-linux-$(LINUX_26VER) tmp-$@ > $@ || true
	rm -rf tmp-$@

mkpatches: linux-$(LINUX_24VER)-xen.patch linux-$(LINUX_26VER)-xen.patch

mrproper:
	rm -rf pristine-linux-$(LINUX_24VER) linux-$(LINUX_24VER).tar.bz2
	rm -rf pristine-linux-$(LINUX_26VER) linux-$(LINUX_26VER).tar.bz2
	rm -rf linux-$(LINUX_24VER)-xen.patch linux-$(LINUX_26VER)-xen.patch
	rm -rf pristine-netbsd-2.0
