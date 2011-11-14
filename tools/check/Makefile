XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

# Export the necessary environment variables for the tests
export PYTHON
export LIBXENAPI_BINDINGS
export CHECK_INCLUDES
export CHECK_LIB

.PHONY: all install
all install: check-build

# Check this machine is OK for building on.
.PHONY: check-build
check-build:
	./chk build

# Check this machine is OK for installing on.
.PHONY: check-install
check-install:
	./chk install

.PHONY: clean
clean:
	./chk clean
