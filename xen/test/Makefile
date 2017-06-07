
tests all: build


ifneq ($(XEN_TARGET_ARCH),x86_32)
# Xen 32-bit x86 hypervisor no longer supported, so has no test livepatches
SUBDIRS += livepatch
endif

%:
	set -e; for s in $(SUBDIRS); do \
		$(MAKE) -f $(BASEDIR)/Rules.mk -C $$s $*; \
	done
