XEN_ROOT=../../../
BLKTAP_ROOT := ../
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
LIBS              += -luuid

# Get gcc to generate the dependencies for us.
CFLAGS            += -Wp,-MD,.$(@F).d
DEPS               = .*.d

all: build

build: $(IBIN)

vhd-util: vhd-util.o subdir-all-lib
	$(CC) $(CFLAGS) -o vhd-util vhd-util.o $(LDFLAGS) $(LIBS)

vhd-update: vhd-update.o subdir-all-lib
	$(CC) $(CFLAGS) -o vhd-update vhd-update.o $(LDFLAGS) $(LIBS)

install: all
	$(INSTALL_DIR) -p $(DESTDIR)$(INST_DIR)
	$(INSTALL_PROG) $(IBIN) $(DESTDIR)$(INST_DIR)

clean:
	rm -rf *.o *~ $(DEPS) $(IBIN)

.PHONY: all build clean install vhd-util vhd-update
all clean install: %: subdirs-%

-include $(DEPS)
