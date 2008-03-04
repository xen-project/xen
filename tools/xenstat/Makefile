XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS :=
SUBDIRS += libxenstat

# This doesn't cross-compile (cross-compile environments rarely have curses)
ifeq ($(XEN_COMPILE_ARCH),$(XEN_TARGET_ARCH))
ifeq ($(wildcard /usr/include/curses.h),/usr/include/curses.h)
SUBDIRS += xentop
endif
endif

.PHONY: all install clean

all install clean:
	@set -e; for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done
