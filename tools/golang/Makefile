XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

# In order to link against a package in Go, the package must live in a
# directory tree in the way that Go expects.  To make this possible,
# there must be a directory such that we can set GOPATH=${dir}, and
# the package will be under $GOPATH/src/${full-package-path}.

# So we set XEN_GOPATH to $XEN_ROOT/tools/golang.  The xenlight
# "package build" directory ($PWD/xenlight) will create the "package
# source" directory in the proper place.  Go programs can use this
# package by setting GOPATH=$(XEN_GOPATH).

SUBDIRS-y = xenlight

.PHONY: build all
all build: subdirs-all

.PHONY: install
install: subdirs-install

.PHONY: uninstall
uninstall: subdirs-uninstall

.PHONY: clean
clean: subdirs-clean
	$(RM) -r src pkg

.PHONY: distclean
distclean: clean
