XEN_ROOT = $(CURDIR)/../../../..
include ../Rules.mk

XG_HDRS := xg_public.h 
XG_OBJS := xg_main.o 

CFLAGS += -D__XEN_TOOLS__
CFLAGS += $(CFLAGS_xeninclude)


.PHONY: all
all: build

.PHONY: build
build: xen-headers xg_all.a $(XG_HDRS) $(XG_OBJS) Makefile
# build: mk-symlinks xg_all.a $(XG_HDRS) $(XG_OBJS) Makefile
# build: mk-symlinks xg_all.a

xg_all.a: $(XG_OBJS) Makefile $(XG_HDRS)
	ar cr $@ $(XG_OBJS)    # problems using -m32 in ld 
#	$(LD) -b elf32-i386 $(LDFLAGS) -r -o $@ $^
#	$(CC) -m32 -c -o $@ $^

xen-headers:
	$(MAKE) -C ../../../include

# xg_main.o: xg_main.c Makefile $(XG_HDRS)
#$(CC) -c $(CFLAGS) -o $@ $<

# %.o: %.c $(XG_HDRS) Makefile  -- doesn't work as it won't overwrite Rules.mk
#%.o: %.c       -- doesn't recompile when .c changed

.PHONY: clean
clean:
	rm -rf xen xg_all.a $(XG_OBJS)  .*.d

.PHONY: distclean
distclean: clean
