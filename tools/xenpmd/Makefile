XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror
CFLAGS  += $(CFLAGS_libxenstore)
LDLIBS += $(LDLIBS_libxenstore)

BIN      = xenpmd

.PHONY: all
all: $(BIN)

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) $(BIN) $(DESTDIR)$(SBINDIR)

.PHONY: clean
clean:
	$(RM) -f $(BIN) $(DEPS)

%: %.c Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(LDLIBS)

-include $(DEPS)
