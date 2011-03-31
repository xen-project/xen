XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror

CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_libxenguest)
CFLAGS += $(CFLAGS_xeninclude)

TARGETS-y := 
TARGETS-$(CONFIG_X86) += xen-access
TARGETS := $(TARGETS-y)

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS)

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) *~ $(DEPS)

xen-access: xen-access.o Makefile
	$(CC) -o $@ $< $(LDFLAGS) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest)

-include $(DEPS)
