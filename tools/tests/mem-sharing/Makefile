XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror

CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_xeninclude)

TARGETS-y := 
TARGETS-$(CONFIG_X86) += memshrtool
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

memshrtool: memshrtool.o
	$(CC) -o $@ $< $(LDFLAGS) $(LDLIBS_libxenctrl)

-include $(DEPS_INCLUDE)
