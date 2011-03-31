XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror

.PHONY: all
all: build

.PHONY: build
build: lomount

.PHONY: install
install install-recurse: build
	$(INSTALL_PROG) $(BIN) $(SCRIPTS) $(DESTDIR)$(BINDIR)

.PHONY: clean
clean:
	$(RM) *.a *.so *.o *.rpm $(BIN)

lomount: lomount.o
	$(CC) $(CFLAGS) -o $@ $< 

-include $(DEPS)