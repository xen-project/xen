XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror

CFLAGS += $(CFLAGS_libxenstore)

TARGETS-y := xs-test
TARGETS := $(TARGETS-y)

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS)

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) *~ $(DEPS_RM)

.PHONY: distclean
distclean: clean

xs-test: xs-test.o Makefile
	$(CC) -o $@ $< $(LDFLAGS) $(LDLIBS_libxenstore)

-include $(DEPS_INCLUDE)
