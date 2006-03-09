ifndef VNET_ROOT
export VNET_ROOT = $(shell cd .. && pwd)
include $(VNET_ROOT)/Make.env
endif

INSTALL		= install
INSTALL_DATA	= $(INSTALL) -m0644
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

include $(XEN_ROOT)/tools/Rules.mk

LIB_SRCS :=
LIB_SRCS += allocate.c
LIB_SRCS += enum.c
LIB_SRCS += file_stream.c
#LIB_SRCS += gzip_stream.c
LIB_SRCS += hash_table.c
LIB_SRCS += iostream.c
LIB_SRCS += lexis.c
LIB_SRCS += mem_stream.c
LIB_SRCS += string_stream.c
LIB_SRCS += sxpr.c
LIB_SRCS += sxpr_parser.c
LIB_SRCS += sys_net.c
LIB_SRCS += sys_string.c
LIB_SRCS += util.c

LIB_OBJS := $(LIB_SRCS:.c=.o)
PIC_OBJS := $(LIB_SRCS:.c=.opic)

CFLAGS   += -Werror -O3 -fno-strict-aliasing -g

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

MAJOR    := 3.0
MINOR    := 0
LIB      := libxutil.so 
LIB      += libxutil.so.$(MAJOR)
LIB      += libxutil.so.$(MAJOR).$(MINOR)
LIB      += libxutil.a

all: build

build: #check-for-zlib
	$(MAKE) $(LIB)

gzip_stream.o: check-for-zlib

libxutil.so: libxutil.so.$(MAJOR)
	ln -sf $^ $@

libxutil.so.$(MAJOR): libxutil.so.$(MAJOR).$(MINOR)
	ln -sf $^ $@

libxutil.so.$(MAJOR).$(MINOR): $(PIC_OBJS)
	$(CC) $(CFLAGS) -Wl,-soname -Wl,libxutil.so.$(MAJOR) -shared -o $@ $^

libxutil.a: $(LIB_OBJS)
	$(AR) rc $@ $^

check-for-zlib:
	@if [ ! -e /usr/include/zlib.h ]; then \
	echo "***********************************************************"; \
	echo "ERROR: install zlib header files (http://www.gzip.org/zlib)"; \
	echo "***********************************************************"; \
	false; \
	fi

install: build
	[ -d $(DESTDIR)/usr/$(LIBDIR) ] || $(INSTALL_DIR) -p $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_PROG) libxutil.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)
	$(INSTALL_DATA) libxutil.a $(DESTDIR)/usr/$(LIBDIR)
	ln -sf libxutil.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/$(LIBDIR)/libxutil.so.$(MAJOR)
	ln -sf libxutil.so.$(MAJOR) $(DESTDIR)/usr/$(LIBDIR)/libxutil.so

clean:
	-@$(RM) *.a *.so* *.o *.opic *.rpm 
	-@$(RM) *~
	-@$(RM) $(DEPS)

-include $(DEPS)
