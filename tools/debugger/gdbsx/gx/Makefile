XEN_ROOT = $(CURDIR)/../../../..
include ../Rules.mk

GX_OBJS := gx_comm.o gx_main.o gx_utils.o gx_local.o
GX_HDRS := $(wildcard *.h)

.PHONY: all
all: gx_all.a

.PHONY: clean
clean:
	rm -rf gx_all.a *.o .*.d


#%.o: %.c $(GX_HDRS) Makefile
#	$(CC) -c $(CFLAGS) -o $@ $<

gx_all.a: $(GX_OBJS) Makefile $(GX_HDRS)
	ar cr $@ $(GX_OBJS)        # problem with ld using -m32 

