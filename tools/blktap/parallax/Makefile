XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

PARALLAX_INSTALL_DIR	= /usr/sbin

INSTALL         = install
INSTALL_PROG    = $(INSTALL) -m0755
INSTALL_DIR     = $(INSTALL) -d -m0755

INCLUDES += -I.. -I/usr/include -I $(XEN_LIBXC)

LDFLAGS = -L.. -lpthread -lz -lblktap

#PLX_SRCS := 
PLX_SRCS := vdi.c 
PLX_SRCS += radix.c 
PLX_SRCS += snaplog.c
PLX_SRCS += blockstore.c 
PLX_SRCS += block-async.c
PLX_SRCS += requests-async.c
VDI_SRCS := $(PLX_SRCS)
PLX_SRCS += parallax.c

#VDI_TOOLS :=
VDI_TOOLS := vdi_create
VDI_TOOLS += vdi_list
VDI_TOOLS += vdi_snap
VDI_TOOLS += vdi_snap_list
VDI_TOOLS += vdi_snap_delete
VDI_TOOLS += vdi_fill
VDI_TOOLS += vdi_tree
VDI_TOOLS += vdi_validate

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -fno-strict-aliasing
CFLAGS   += $(INCLUDES)
CFLAGS   += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

OBJS     = $(patsubst %.c,%.o,$(SRCS))
IBINS    = parallax $(VDI_TOOLS)

.PHONY: all
all: $(VDI_TOOLS) parallax blockstored

.PHONY: install
install: all
	$(INSTALL_PROG) $(IBINS) $(DESTDIR)$(PARALLAX_INSTALL_DIR)

.PHONY: clean
clean:
	rm -rf *.o *~ $(DEPS) xen TAGS $(VDI_TOOLS) parallax vdi_unittest

parallax: $(PLX_SRCS)
	$(CC) $(CFLAGS) -o parallax -L.. $(LDFLAGS) $(PLX_SRCS)

${VDI_TOOLS}: %: %.c $(VDI_SRCS)
	$(CC) $(CFLAGS) -o $@ $@.c $(LDFLAGS) $(VDI_SRCS)

-include $(DEPS)
