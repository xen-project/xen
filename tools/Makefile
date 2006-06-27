XEN_ROOT = ../
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += libxc
SUBDIRS-y += xenstore
SUBDIRS-y += misc
SUBDIRS-y += examples
SUBDIRS-y += xentrace
SUBDIRS-$(CONFIG_X86) += xcutils
SUBDIRS-y += firmware
SUBDIRS-y += security
SUBDIRS-y += console
SUBDIRS-y += xenmon
SUBDIRS-y += guest-headers
SUBDIRS-$(VTPM_TOOLS) += vtpm_manager
SUBDIRS-$(VTPM_TOOLS) += vtpm
SUBDIRS-y += xenstat

# These don't cross-compile
ifeq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
SUBDIRS-y += python
SUBDIRS-y += pygrub
endif

.PHONY: all
all: check
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) -C $$subdir $@; \
	done
	$(MAKE) ioemu

.PHONY: install
install: check
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) -C $$subdir $@; \
	done
	$(MAKE) ioemuinstall
	$(INSTALL_DIR) -p $(DESTDIR)/var/xen/dump

.PHONY: clean
clean: check_clean
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) -C $$subdir $@; \
	done
	$(MAKE) ioemuclean

.PHONY: distclean
distclean: clean

.PHONY: check
check:
	$(MAKE) -C check

.PHONY: check_clean
check_clean:
	$(MAKE) -C check clean

.PHONY: ioemu ioemuinstall ioemuclean
ifdef CONFIG_IOEMU
ioemu ioemuinstall ioemuclean:
	[ -f ioemu/config-host.h ] || \
	(cd ioemu; sh ./configure --prefix=usr)
	$(MAKE) -C ioemu $(patsubst ioemu%,%,$@)
else
ioemu ioemuinstall ioemuclean:
endif

