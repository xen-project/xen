XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Make.defs

CC = gcc

LIB_SRCS :=
LIB_SRCS += allocate.c
#LIB_SRCS += enum.c
LIB_SRCS += file_stream.c
LIB_SRCS += gzip_stream.c
#LIB_SRCS += hash_table.c
LIB_SRCS += iostream.c
#LIB_SRCS += kernel_stream.c
#LIB_SRCS += lexis.c
#LIB_SRCS += lzi_stream.c
#LIB_SRCS += lzo_stream.c
#LIB_SRCS += marshal.c
#LIB_SRCS += socket_stream.c
#LIB_SRCS += string_stream.c
#LIB_SRCS += sxpr.c
#LIB_SRCS += sxpr_parser.c
LIB_SRCS += sys_net.c
LIB_SRCS += sys_string.c
#LIB_SRCS += xdr.c

LIB_OBJS := $(LIB_SRCS:.c=.o)

CFLAGS   += -Wall
CFLAGS   += -Werror
CFLAGS   += -g
CFLAGS   += -O3
CFLAGS   += -fno-strict-aliasing
#CFLAGS   += $(INCLUDES)
# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

MAJOR    = 1.3
MINOR    = 0
LIB_NAME = libxutil
LIB_BASE = $(LIB_NAME).so
LIB_MAJOR= $(LIB_BASE).$(MAJOR)
LIB_MINOR= $(LIB_MAJOR).$(MINOR)
LIB      = $(LIB_BASE) $(LIB_MAJOR) $(LIB_MINOR) $(LIB_NAME).a

all: check-for-zlib $(LIB)

$(LIB_BASE):
	ln -sf $(LIB_MAJOR) $@

$(LIB_MAJOR):
	ln -sf $(LIB_MINOR) $@

$(LIB_MINOR): $(LIB_OBJS)
	$(CC) -Wl,-soname -Wl,$(LIB_MAJOR) -shared -o $@ $^

$(LIB_NAME).a: $(LIB_OBJS)
	$(AR) rc $@ $^

check-for-zlib:
	@if [ ! -e /usr/include/zlib.h ]; then \
	echo "***********************************************************"; \
	echo "ERROR: install zlib header files (http://www.gzip.org/zlib)"; \
	echo "***********************************************************"; \
	false; \
	fi

install: all
	mkdir -p $(prefix)/usr/lib
	mkdir -p $(prefix)/usr/include
	install -m0755 $(LIB) $(prefix)/usr/lib

#install -m0644 xc.h $(prefix)/usr/include

clean:
	$(RM) *.a *.so *.o *.rpm $(LIB)
	$(RM) *~
	$(RM) $(DEPS)

-include $(DEPS)
