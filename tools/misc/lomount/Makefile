XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror

.PHONY: all
all: build

.PHONY: build
build: lomount

.PHONY: install
install install-recurse: build
	$(INSTALL_PROG) lomount $(SCRIPTS) $(DESTDIR)$(BINDIR)

.PHONY: clean
clean:
	$(RM) *.o lomount

lomount: lomount.o
	$(CC) $(CFLAGS) -o $@ $< 

-include $(DEPS)