XEN_ROOT = $(CURDIR)/../../../..
include ../Rules.mk

XG_OBJS := xg_main.o 

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(CFLAGS_xeninclude)

TARGETS := xg_all.a

.PHONY: all
all: $(TARGETS)

xg_all.a: $(XG_OBJS) Makefile
	$(AR) cr $@ $(XG_OBJS)

.PHONY: clean
clean:
	rm -f $(TARGETS) $(XG_OBJS) $(DEPS_RM)

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)
