XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all install
all install: check-build

# Check this machine is OK for building on.
.PHONY: check-build
check-build:
	PYTHON=$(PYTHON) LIBXENAPI_BINDINGS=$(LIBXENAPI_BINDINGS) ACM_SECURITY=$(ACM_SECURITY) ./chk build

# Check this machine is OK for installing on.
.PHONY: check-install
check-install:
	PYTHON=$(PYTHON) LIBXENAPI_BINDINGS=$(LIBXENAPI_BINDINGS) ACM_SECURITY=$(ACM_SECURITY) ./chk install

.PHONY: clean
clean:
	./chk clean
