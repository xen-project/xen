XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += lib
SUBDIRS-y += drivers

.PHONY: all
all: build

.PHONY: build
build: mk-symlinks
	@set -e; for subdir in $(SUBDIRS-y); do \
	$(MAKE) -C $$subdir all;       \
		done

.PHONY: install
install:
	@set -e; for subdir in $(SUBDIRS-y); do \
		$(MAKE) -C $$subdir install; \
	done

.PHONY: clean
clean:
	rm -rf *.a *.so *.o *.rpm $(LIB) *~ $(DEPS) xen TAGS
	@set -e; for subdir in $(SUBDIRS-y); do \
	$(MAKE) -C $$subdir clean;       \
		done
