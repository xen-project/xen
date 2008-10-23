XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror
CFLAGS  += $(CFLAGS_libxenstore)
LDFLAGS += $(LDFLAGS_libxenstore)

BIN      = xenpmd

.PHONY: all
all: $(BIN)

.PHONY: clean
clean:
	$(RM) -f $(BIN)
