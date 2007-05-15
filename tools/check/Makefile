XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: build

# Check this machine is OK for building on.
.PHONY: build
build:
	XENFB_TOOLS=$(XENFB_TOOLS) LIBXENAPI_BINDINGS=$(LIBXENAPI_BINDINGS) ./chk build

# Check this machine is OK for installing on.
# DO NOT use this check from 'make install' in the parent
# directory, as that target can be used to make an installable
# copy rather than actually installing.
.PHONY: install
install:
	XENFB_TOOLS=$(XENFB_TOOLS) LIBXENAPI_BINDINGS=$(LIBXENAPI_BINDINGS) ./chk install

.PHONY: clean
clean:
	./chk clean
