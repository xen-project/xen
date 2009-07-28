#
# Sets up some regression applications
# Runs regression tests
#
# To run this, at least the basic build / development environment must
# be installed (gcc, ...)
#
XEN_ROOT=${PWD}/..

PYTHON_VERSIONS=python-2.3 python-2.4 python-2.5 python-2.6 python-3.1

.PHONY: all
all: check-python-syntax

.PHONY: check-python-syntax
check-python-syntax: runtime-environment
	@(set -e && for p in ${PYTHON_VERSIONS}; do \
	  ${XEN_ROOT}/tests/scripts/check_python_syntax.sh ${XEN_ROOT} $$p; done)

.PHONY: runtime-environment
runtime-environment: ${PYTHON_VERSIONS}

.PHONY: dist-clean
dist-clean:
	rm -fr ${XEN_ROOT}/tests/installed ${XEN_ROOT}/tests/downloads \
		${XEN_ROOT}/tests/build

### Python 2.3

.PHONY: python-2.3
python-2.3: ${XEN_ROOT}/tests/installed/python-2.3/bin/python2.3

${XEN_ROOT}/tests/installed/python-2.3/bin/python2.3: \
	${XEN_ROOT}/tests/downloads/Python-2.3.7.tgz
	@${XEN_ROOT}/tests/scripts/build_python.sh ${XEN_ROOT} 2.3 2.3.7
${XEN_ROOT}/tests/downloads/Python-2.3.7.tgz:
	@${XEN_ROOT}/tests/scripts/download_python.sh ${XEN_ROOT} 2.3.7

### Python 2.4

.PHONY: python-2.4
python-2.4: ${XEN_ROOT}/tests/installed/python-2.4/bin/python2.4

${XEN_ROOT}/tests/installed/python-2.4/bin/python2.4: \
	${XEN_ROOT}/tests/downloads/Python-2.4.6.tgz
	@${XEN_ROOT}/tests/scripts/build_python.sh ${XEN_ROOT} 2.4 2.4.6
${XEN_ROOT}/tests/downloads/Python-2.4.6.tgz:
	@${XEN_ROOT}/tests/scripts/download_python.sh ${XEN_ROOT} 2.4.6

### Python 2.5

.PHONY: python-2.5
python-2.5: ${XEN_ROOT}/tests/installed/python-2.5/bin/python2.5

${XEN_ROOT}/tests/installed/python-2.5/bin/python2.5: \
	${XEN_ROOT}/tests/downloads/Python-2.5.4.tgz
	@${XEN_ROOT}/tests/scripts/build_python.sh ${XEN_ROOT} 2.5 2.5.4
${XEN_ROOT}/tests/downloads/Python-2.5.4.tgz:
	@${XEN_ROOT}/tests/scripts/download_python.sh ${XEN_ROOT} 2.5.4

### Python 2.6

.PHONY: python-2.6
python-2.6: ${XEN_ROOT}/tests/installed/python-2.6/bin/python2.6

${XEN_ROOT}/tests/installed/python-2.6/bin/python2.6: \
	${XEN_ROOT}/tests/downloads/Python-2.6.2.tgz
	@${XEN_ROOT}/tests/scripts/build_python.sh ${XEN_ROOT} 2.6 2.6.2
${XEN_ROOT}/tests/downloads/Python-2.6.2.tgz:
	@${XEN_ROOT}/tests/scripts/download_python.sh ${XEN_ROOT} 2.6.2

### Python 3.0.1 has reached end of life and is not (longer) supported

### Python 3.1

.PHONY: python-3.1
python-3.1: ${XEN_ROOT}/tests/installed/python-3.1/bin/python3.1

${XEN_ROOT}/tests/installed/python-3.1/bin/python3.1: \
	${XEN_ROOT}/tests/downloads/Python-3.1.tgz
	@${XEN_ROOT}/tests/scripts/build_python.sh ${XEN_ROOT} 3.1 3.1
${XEN_ROOT}/tests/downloads/Python-3.1.tgz:
	@${XEN_ROOT}/tests/scripts/download_python.sh ${XEN_ROOT} 3.1
