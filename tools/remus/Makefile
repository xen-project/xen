XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

SCRIPTS = remus

.PHONY: all
all: build

.PHONY: build
build:
       echo "Nothing to do"

.PHONY: install
install:
       $(INSTALL_DIR) $(DESTDIR)$(BINDIR)
       $(INSTALL_PYTHON_PROG) $(SCRIPTS) $(DESTDIR)$(BINDIR)

.PHONY: clean
clean:
       echo "Nothing to do"
