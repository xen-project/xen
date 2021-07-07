XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

# Standing boldly against convention, we insist on installing the
# package source under $(prefix)/share/gocode
GOCODE_DIR ?= $(prefix)/share/gocode/
GOXL_INSTALL_DIR = $(GOCODE_DIR)/src/$(XEN_GOCODE_URL)/xenlight/

GO ?= go

LIBXL_SRC_DIR = $(XEN_ROOT)/tools/libs/light

.PHONY: all
all: build

GOXL_GEN_FILES = types.gen.go helpers.gen.go

%.gen.go: gengotypes.py $(LIBXL_SRC_DIR)/libxl_types.idl $(LIBXL_SRC_DIR)/idl.py
	LIBXL_SRC_DIR=$(LIBXL_SRC_DIR) $(PYTHON) gengotypes.py $(LIBXL_SRC_DIR)/libxl_types.idl

# Go will do its own dependency checking, and not actuall go through
# with the build if none of the input files have changed.
#
# NB that because the users of this library need to be able to
# recompile the library from source, it needs to include '-lxenlight'
# in the LDFLAGS; and thus we need to add -L$(XEN_libxenlight) here
# so that it can find the actual library.
.PHONY: build
build: xenlight.go $(GOXL_GEN_FILES)
	CGO_CFLAGS="$(CFLAGS_libxenlight) $(CFLAGS_libxentoollog) $(APPEND_CFLAGS)" CGO_LDFLAGS="$(LDLIBS_libxenlight) $(LDLIBS_libxentoollog) -L$(XEN_libxenlight) -L$(XEN_libxentoollog) $(APPEND_LDFLAGS)" $(GO) build -x

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
