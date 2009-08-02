#
# Sets up some regression applications
# Runs regression tests
#
# To run this, at least the basic build / development environment must
# be installed (gcc, ...)
#
XEN_ROOT=$(PWD)/../../..
REG_TEST_DIR=$(PWD)

PYTHON_VERSIONS=python-2.3 python-2.4 python-2.5 python-2.6 python-3.1

.PHONY: all
all: check-python-syntax

.PHONY: check-python-syntax
check-python-syntax: runtime-environment
	@(set -e && for p in $(PYTHON_VERSIONS); do \
	  /bin/sh $(REG_TEST_DIR)/scripts/check_python_syntax.sh \
		$(REG_TEST_DIR) $$p $(XEN_ROOT); done)

.PHONY: runtime-environment
runtime-environment: $(PYTHON_VERSIONS)

.PHONY: dist-clean
dist-clean:
	rm -fr $(REG_TEST_DIR)/installed $(REG_TEST_DIR)/downloads \
		$(REG_TEST_DIR)/build

### Python 2.3

.PHONY: python-2.3
python-2.3: $(REG_TEST_DIR)/installed/python-2.3/bin/python2.3

$(REG_TEST_DIR)/installed/python-2.3/bin/python2.3: \
	$(REG_TEST_DIR)/downloads/Python-2.3.7.tgz
	@/bin/sh $(REG_TEST_DIR)/scripts/build_python.sh \
		$(REG_TEST_DIR) 2.3 2.3.7
$(REG_TEST_DIR)/downloads/Python-2.3.7.tgz:
	@/bin/sh $(REG_TEST_DIR)/scripts/download_python.sh \
		$(REG_TEST_DIR) 2.3.7

### Python 2.4

.PHONY: python-2.4
python-2.4: $(REG_TEST_DIR)/installed/python-2.4/bin/python2.4

$(REG_TEST_DIR)/installed/python-2.4/bin/python2.4: \
	$(REG_TEST_DIR)/downloads/Python-2.4.6.tgz
	@/bin/sh $(REG_TEST_DIR)/scripts/build_python.sh \
		$(REG_TEST_DIR) 2.4 2.4.6
$(REG_TEST_DIR)/downloads/Python-2.4.6.tgz:
	@/bin/sh $(REG_TEST_DIR)/scripts/download_python.sh \
		$(REG_TEST_DIR) 2.4.6

### Python 2.5

.PHONY: python-2.5
python-2.5: $(REG_TEST_DIR)/installed/python-2.5/bin/python2.5

$(REG_TEST_DIR)/installed/python-2.5/bin/python2.5: \
	$(REG_TEST_DIR)/downloads/Python-2.5.4.tgz
	@/bin/sh $(REG_TEST_DIR)/scripts/build_python.sh \
		$(REG_TEST_DIR) 2.5 2.5.4
$(REG_TEST_DIR)/downloads/Python-2.5.4.tgz:
	@/bin/sh $(REG_TEST_DIR)/scripts/download_python.sh \
		$(REG_TEST_DIR) 2.5.4

### Python 2.6

.PHONY: python-2.6
python-2.6: $(REG_TEST_DIR)/installed/python-2.6/bin/python2.6

$(REG_TEST_DIR)/installed/python-2.6/bin/python2.6: \
	$(REG_TEST_DIR)/downloads/Python-2.6.2.tgz
	@/bin/sh $(REG_TEST_DIR)/scripts/build_python.sh \
		$(REG_TEST_DIR) 2.6 2.6.2
$(REG_TEST_DIR)/downloads/Python-2.6.2.tgz:
	@/bin/sh $(REG_TEST_DIR)/scripts/download_python.sh \
		$(REG_TEST_DIR) 2.6.2

### Python 3.0.1 has reached end of life and is not (longer) supported

### Python 3.1

.PHONY: python-3.1
python-3.1: $(REG_TEST_DIR)/installed/python-3.1/bin/python3.1

$(REG_TEST_DIR)/installed/python-3.1/bin/python3.1: \
	$(REG_TEST_DIR)/downloads/Python-3.1.tgz
	@/bin/sh $(REG_TEST_DIR)/scripts/build_python.sh \
		$(REG_TEST_DIR) 3.1 3.1
$(REG_TEST_DIR)/downloads/Python-3.1.tgz:
	@/bin/sh $(REG_TEST_DIR)/scripts/download_python.sh \
		$(REG_TEST_DIR) 3.1
