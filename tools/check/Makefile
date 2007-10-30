XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: build

# Check this machine is OK for building on.
.PHONY: build
build:
	LIBXENAPI_BINDINGS=$(LIBXENAPI_BINDINGS) ACM_SECURITY=$(ACM_SECURITY) ./chk build

# Check this machine is OK for installing on.
# DO NOT use this check from 'make install' in the parent
# directory, as that target can be used to make an installable
# copy rather than actually installing.
.PHONY: install
install:
	LIBXENAPI_BINDINGS=$(LIBXENAPI_BINDINGS) ACM_SECURITY=$(ACM_SECURITY) ./chk install

.PHONY: clean
clean:
	./chk clean
