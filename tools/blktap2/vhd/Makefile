XEN_ROOT=$(CURDIR)/../../..
BLKTAP_ROOT := ..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y         :=
SUBDIRS-y         += lib

IBIN               = vhd-util vhd-update
INST_DIR           = $(SBINDIR)

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

LIBS              := -Llib -lvhd

all: subdirs-all build

build: $(IBIN)

LIBS_DEPENDS	  := lib/libvhd.so lib/vhd.a
$(LIBS_DEPENDS):subdirs-all

vhd-util: vhd-util.o $(LIBS_DEPENDS)
	$(CC) $(LDFLAGS) -o vhd-util vhd-util.o $(LIBS) $(APPEND_LDFLAGS)

vhd-update: vhd-update.o $(LIBS_DEPENDS)
	$(CC) $(LDFLAGS) -o vhd-update vhd-update.o $(LIBS) $(APPEND_LDFLAGS)

install: all
	$(MAKE) subdirs-install
	$(INSTALL_DIR) -p $(DESTDIR)$(INST_DIR)
	$(INSTALL_PROG) $(IBIN) $(DESTDIR)$(INST_DIR)

clean: subdirs-clean
	rm -rf *.o *~ $(DEPS) $(IBIN)

.PHONY: all build clean install vhd-util vhd-update

-include $(DEPS)
