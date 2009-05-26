XEN_ROOT=../../../
BLKTAP_ROOT := ../
include $(XEN_ROOT)/tools/Rules.mk

IBIN               = vhd-util vhd-update
INST_DIR           = $(SBINDIR)

LIBDIR             = lib

CFLAGS            += -Werror
CFLAGS            += -Wno-unused
CFLAGS            += -I../include
CFLAGS            += -D_GNU_SOURCE

ifeq ($(CONFIG_X86_64),y)
CFLAGS            += -fPIC
endif

ifeq ($(VHD_STATIC),y)
CFLAGS            += -static
endif

LIBS              := -L$(LIBDIR) -lvhd
LIBS              += -luuid

# Get gcc to generate the dependencies for us.
CFLAGS            += -Wp,-MD,.$(@F).d
DEPS               = .*.d

all: build

build: libvhd $(IBIN)

libvhd:
	@set -e
	$(MAKE) -C $(LIBDIR) all

vhd-util: vhd-util.o
	$(CC) $(CFLAGS) -o vhd-util vhd-util.o $(LIBS)

vhd-update: vhd-update.o
	$(CC) $(CFLAGS) -o vhd-update vhd-update.o $(LIBS)

install: all
	$(MAKE) -C $(LIBDIR) install
	$(INSTALL_DIR) -p $(DESTDIR)$(INST_DIR)
	$(INSTALL_PROG) $(IBIN) $(DESTDIR)$(INST_DIR)

clean:
	$(MAKE) -C $(LIBDIR) clean
	rm -rf *.o *~ $(DEPS) $(IBIN)

.PHONY: all build clean install libvhd vhd-util vhd-update

-include $(DEPS)
