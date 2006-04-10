XEN_ROOT = ../
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS :=
SUBDIRS += libxc
SUBDIRS += xenstore
SUBDIRS += misc
SUBDIRS += examples
SUBDIRS += xentrace
SUBDIRS += xcutils
SUBDIRS += firmware
SUBDIRS += security
SUBDIRS += console
SUBDIRS += xenmon
SUBDIRS += guest-headers
ifeq ($(VTPM_TOOLS),y)
SUBDIRS += vtpm_manager
SUBDIRS += vtpm
endif
SUBDIRS += xenstat
# These don't cross-compile
ifeq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
SUBDIRS += python
SUBDIRS += pygrub
endif

.PHONY: all
all: check
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done
	$(MAKE) ioemu

.PHONY: install
install: check
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done
	$(MAKE) ioemuinstall
	$(INSTALL_DIR) -p $(DESTDIR)/var/xen/dump

.PHONY: clean
clean: check_clean
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done
	$(MAKE) ioemuclean

.PHONY: check
check:
	$(MAKE) -C check

.PHONY: check_clean
check_clean:
	$(MAKE) -C check clean

.PHONY: ioemu ioemuinstall ioemuclean
ifndef XEN_NO_IOEMU
ioemu ioemuinstall ioemuclean:
	[ -f ioemu/config-host.h ] || \
	(cd ioemu; ./configure --prefix=usr)
	$(MAKE) -C ioemu $(patsubst ioemu%,%,$@)
else
ioemu ioemuinstall ioemuclean:
endif

