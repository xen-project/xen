
ifndef BUILD_PIC_LIBS
ifeq ($(wildcard /etc/debian_version),)
BUILD_PIC_LIBS=n
else
BUILD_PIC_LIBS=y
endif
endif

XEN_ROOT = ../..
INSTALL		= install
INSTALL_DATA	= $(INSTALL) -m0644
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DIR	= $(INSTALL) -d -m0755

include $(XEN_ROOT)/tools/Rules.mk

CC = gcc

LIB_SRCS :=
LIB_SRCS += allocate.c
LIB_SRCS += enum.c
LIB_SRCS += file_stream.c
LIB_SRCS += gzip_stream.c
LIB_SRCS += hash_table.c
LIB_SRCS += iostream.c
LIB_SRCS += lexis.c
LIB_SRCS += string_stream.c
LIB_SRCS += sxpr.c
LIB_SRCS += sxpr_parser.c
LIB_SRCS += sys_net.c
LIB_SRCS += sys_string.c
LIB_SRCS += util.c

LIB_OBJS := $(LIB_SRCS:.c=.o)
PIC_OBJS := $(LIB_SRCS:.c=.opic)

CFLAGS   += -Wall -Werror -O3 -fno-strict-aliasing

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

MAJOR    := 3.0
MINOR    := 0
LIB      := libxutil.so 
LIB      += libxutil.so.$(MAJOR)
LIB      += libxutil.so.$(MAJOR).$(MINOR)
LIB      += libxutil.a

all: check-for-zlib
	$(MAKE) $(LIB)

$(PIC_OBJS): %.opic: %.c
	$(CC) $(CPPFLAGS) -DPIC $(CFLAGS) -fPIC -c -o $@ $<

libxutil.so: libxutil.so.$(MAJOR)
	ln -sf $^ $@

libxutil.so.$(MAJOR): libxutil.so.$(MAJOR).$(MINOR)
	ln -sf $^ $@

ifeq ($(BUILD_PIC_LIBS),y)
libxutil.so.$(MAJOR).$(MINOR): $(PIC_OBJS)
	$(CC) -Wl,-soname -Wl,libxutil.so.$(MAJOR) -shared -o $@ $^
else
libxutil.so.$(MAJOR).$(MINOR): $(LIB_OBJS)
	$(CC) -Wl,-soname -Wl,libxutil.so.$(MAJOR) -shared -o $@ $^
endif

libxutil.a: $(LIB_OBJS)
	$(AR) rc $@ $^

check-for-zlib:
	@if [ ! -e /usr/include/zlib.h ]; then \
	echo "***********************************************************"; \
	echo "ERROR: install zlib header files (http://www.gzip.org/zlib)"; \
	echo "***********************************************************"; \
	false; \
	fi

install: all
	[ -d $(DESTDIR)/usr/lib ] || $(INSTALL_DIR) -p $(DESTDIR)/usr/lib
	$(INSTALL_PROG) libxutil.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/lib
	$(INSTALL_DATA) libxutil.a $(DESTDIR)/usr/lib
	ln -sf libxutil.so.$(MAJOR).$(MINOR) $(DESTDIR)/usr/lib/libxutil.so.$(MAJOR)
	ln -sf libxutil.so.$(MAJOR) $(DESTDIR)/usr/lib/libxutil.so

clean:
	$(RM) *.a *.so* *.o *.opic *.rpm 
	$(RM) *~
	$(RM) $(DEPS)

-include $(DEPS)
