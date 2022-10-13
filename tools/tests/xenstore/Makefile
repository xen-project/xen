XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGETS-y := test-xenstore
TARGETS := $(TARGETS-y)

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS)

.PHONY: clean
clean:
	$(RM) -- *.o $(TARGETS) $(DEPS_RM)

.PHONY: distclean
distclean: clean
	$(RM) -- *~

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(if $(TARGETS),$(INSTALL_PROG) $(TARGETS) $(DESTDIR)$(LIBEXEC_BIN))

.PHONY: uninstall
uninstall:
	$(RM) -- $(addprefix $(DESTDIR)$(LIBEXEC_BIN)/,$(TARGETS))

CFLAGS += $(CFLAGS_libxenstore)
CFLAGS += $(APPEND_CFLAGS)

LDFLAGS += $(LDLIBS_libxenstore)
LDFLAGS += $(APPEND_LDFLAGS)
ifeq ($(CONFIG_Linux),y)
LDFLAGS += -Wl,--as-needed -lc -lrt
endif

%.o: Makefile

test-xenstore: test-xenstore.o
	$(CC) -o $@ $< $(LDFLAGS)

-include $(DEPS_INCLUDE)
