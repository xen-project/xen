XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -Werror

INCLUDES += -I $(XEN_XC)
INCLUDES += -I $(XEN_LIBXC)
INCLUDES += -I $(XEN_INCLUDE)
CFLAGS   += $(INCLUDES)

TARGETS-y := 
TARGETS-$(CONFIG_X86) += xen-access
TARGETS := $(TARGETS-y)

SUBDIRS-y :=
SUBDIRS := $(SUBDIRS-y)

.PHONY: all
all: build

.PHONY: build
build: $(TARGETS)
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d; done

.PHONY: clean
clean:
	$(RM) *.o $(TARGETS) *~ $(DEPS)
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d clean; done

%.o: %.c Makefile
	$(CC) -c $(CFLAGS) -o $@ $<

xen-access: %: %.o Makefile
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS_libxenctrl)
# $(LDLIBS_libxenguest) $(LDLIBS_libxenstore)
-include $(DEPS)
