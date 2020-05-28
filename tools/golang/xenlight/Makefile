XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

# Standing boldly against convention, we insist on installing the
# package source under $(prefix)/share/gocode
GOCODE_DIR ?= $(prefix)/share/gocode/
GOXL_INSTALL_DIR = $(GOCODE_DIR)/src/$(XEN_GOCODE_URL)/xenlight/

GO ?= go

LIBXL_SRC_DIR = ../../libxl

.PHONY: all
all: build

GOXL_GEN_FILES = types.gen.go helpers.gen.go

# NOTE: This target is called from libxl/Makefile:all.  Since that
# target must finish before golang/Makefile is called, this is
# currently safe.  It must not be called from anywhere else in the
# Makefile system without careful thought about races with
# xenlight/Makefile:all
idl-gen: $(GOXL_GEN_FILES)

%.gen.go: gengotypes.py $(LIBXL_SRC_DIR)/libxl_types.idl $(LIBXL_SRC_DIR)/idl.py
	XEN_ROOT=$(XEN_ROOT) $(PYTHON) gengotypes.py $(LIBXL_SRC_DIR)/libxl_types.idl

# Go will do its own dependency checking, and not actuall go through
# with the build if none of the input files have changed.
#
# NB that because the users of this library need to be able to
# recompile the library from source, it needs to include '-lxenlight'
# in the LDFLAGS; and thus we need to add -L$(XEN_XENLIGHT) here
# so that it can find the actual library.
.PHONY: build
build: xenlight.go $(GOXL_GEN_FILES)
	CGO_CFLAGS="$(CFLAGS_libxenlight) $(CFLAGS_libxentoollog)" CGO_LDFLAGS="$(LDLIBS_libxenlight) $(LDLIBS_libxentoollog) -L$(XEN_XENLIGHT) -L$(XEN_LIBXENTOOLLOG)" $(GO) build -x

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(GOXL_INSTALL_DIR)
	$(INSTALL_DATA) xenlight.go $(DESTDIR)$(GOXL_INSTALL_DIR)
	$(INSTALL_DATA) types.gen.go $(DESTDIR)$(GOXL_INSTALL_DIR)
	$(INSTALL_DATA) helpers.gen.go $(DESTDIR)$(GOXL_INSTALL_DIR)

.PHONY: uninstall
	rm -rf $(DESTDIR)$(GOXL_INSTALL_DIR)

.PHONY: clean
clean:

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)
