XEN_ROOT = $(CURDIR)/../../../..
include ../Rules.mk

GX_OBJS := gx_comm.o gx_main.o gx_utils.o gx_local.o

TARGETS := gx_all.a

.PHONY: all
all: $(TARGETS)

.PHONY: clean
clean:
	rm -f *.o $(TARGETS) $(DEPS_RM)

.PHONY: distclean
distclean: clean

gx_all.a: $(GX_OBJS) Makefile
	$(AR) cr $@ $(GX_OBJS)

-include $(DEPS_INCLUDE)
