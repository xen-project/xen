XEN_ROOT=$(CURDIR)/../../../..
BLKTAP_ROOT := ../..
include $(XEN_ROOT)/tools/Rules.mk

LIBVHD-MAJOR     = 1.0
LIBVHD-MINOR     = 0
LIBVHD-SONAME    = libvhd.so.$(LIBVHD-MAJOR)

LVM-UTIL-OBJ    := $(BLKTAP_ROOT)/lvm/lvm-util.o

LIBVHD-BUILD    := libvhd.a

INST-DIR         = $(LIBDIR)

CFLAGS          += -Werror
CFLAGS          += -Wno-unused
CFLAGS          += -I../../include
CFLAGS          += -D_GNU_SOURCE
CFLAGS          += -fPIC

ifeq ($(CONFIG_Linux),y)
LIBS            := -luuid
endif

ifeq ($(CONFIG_LIBICONV),y)
LIBS            += -liconv
endif

LIB-SRCS        := libvhd.c
LIB-SRCS        += libvhd-journal.c
LIB-SRCS        += vhd-util-coalesce.c
LIB-SRCS        += vhd-util-create.c
LIB-SRCS        += vhd-util-fill.c
LIB-SRCS        += vhd-util-modify.c
LIB-SRCS        += vhd-util-query.c
LIB-SRCS        += vhd-util-read.c
LIB-SRCS        += vhd-util-repair.c
LIB-SRCS        += vhd-util-resize.c
LIB-SRCS        += vhd-util-revert.c
LIB-SRCS        += vhd-util-set-field.c
LIB-SRCS        += vhd-util-snapshot.c
LIB-SRCS        += vhd-util-scan.c
LIB-SRCS        += vhd-util-check.c
LIB-SRCS        += vhd-util-uuid.c
LIB-SRCS        += relative-path.c
LIB-SRCS        += atomicio.c

LIB-OBJS         = $(patsubst %.c,%.o,$(LIB-SRCS))
LIB-OBJS        += $(LVM-UTIL-OBJ)

LIB-PICOBJS      = $(patsubst %.o,%.opic,$(LIB-OBJS))

LIBVHD           = libvhd.a libvhd.so.$(LIBVHD-MAJOR).$(LIBVHD-MINOR)

all: build

build: libvhd.a libvhd.so.$(LIBVHD-MAJOR).$(LIBVHD-MINOR)

libvhd.a: $(LIB-OBJS)
	$(AR) rc $@ $^

libvhd.so.$(LIBVHD-MAJOR).$(LIBVHD-MINOR): $(LIB-PICOBJS)
	$(CC) -Wl,$(SONAME_LDFLAG),$(LIBVHD-SONAME) $(SHLIB_LDFLAGS) \
		$(LDFLAGS) -o libvhd.so.$(LIBVHD-MAJOR).$(LIBVHD-MINOR) $^ $(LIBS)
	ln -sf libvhd.so.$(LIBVHD-MAJOR).$(LIBVHD-MINOR) libvhd.so.$(LIBVHD-MAJOR)
	ln -sf libvhd.so.$(LIBVHD-MAJOR) libvhd.so

install: all
	$(INSTALL_DIR) -p $(DESTDIR)$(INST-DIR)
	$(INSTALL_DATA) libvhd.a $(DESTDIR)$(INST-DIR)
	$(INSTALL_PROG) libvhd.so.$(LIBVHD-MAJOR).$(LIBVHD-MINOR) $(DESTDIR)$(INST-DIR)
	ln -sf libvhd.so.$(LIBVHD-MAJOR).$(LIBVHD-MINOR) $(DESTDIR)$(INST-DIR)/libvhd.so.$(LIBVHD-MAJOR)
	ln -sf libvhd.so.$(LIBVHD-MAJOR) $(DESTDIR)$(INST-DIR)/libvhd.so

clean:
	rm -rf *.a *.so* *.o *.opic *~ $(DEPS) $(LIBVHD)

.PHONY: all build clean install libvhd

-include $(DEPS)
