XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Make.defs

CC = gcc

LIB_SRCS :=
LIB_SRCS += allocate.c
LIB_SRCS += file_stream.c
LIB_SRCS += gzip_stream.c
LIB_SRCS += iostream.c
#LIB_SRCS += sys_net.c
LIB_SRCS += sys_string.c

LIB_OBJS := $(LIB_SRCS:.c=.o)

CFLAGS   += -Wall
CFLAGS   += -Werror
CFLAGS   += -g
CFLAGS   += -O3
CFLAGS   += -fno-strict-aliasing

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

MAJOR    := 1.3
MINOR    := 0
LIB_NAME := libxutil
LIB      := $(LIB_NAME).so 
LIB      += $(LIB_NAME).so.$(MAJOR)
LIB      += $(LIB_NAME).so.$(MAJOR).$(MINOR)

all: check-for-zlib
	$(MAKE) $(LIB)

$(LIB_NAME).so: $(LIB_NAME).so.$(MAJOR)
	ln -sf $^ $@

$(LIB_NAME).so.$(MAJOR): $(LIB_NAME).so.$(MAJOR).$(MINOR)
	ln -sf $^ $@

$(LIB_NAME).so.$(MAJOR).$(MINOR): $(LIB_OBJS)
	$(CC) -Wl,-soname -Wl,$(LIB_NAME).so.$(MAJOR) -shared -o $@ $^

check-for-zlib:
	@if [ ! -e /usr/include/zlib.h ]; then \
	echo "***********************************************************"; \
	echo "ERROR: install zlib header files (http://www.gzip.org/zlib)"; \
	echo "***********************************************************"; \
	false; \
	fi

install: all
	mkdir -p $(prefix)/usr/lib
	install -m0755 $(LIB) $(prefix)/usr/lib
	ln -sf $(LIB_NAME).so.$(MAJOR).$(MINOR) $(prefix)/usr/lib/$(LIB_NAME).so.$(MAJOR)
	ln -sf $(LIB_NAME).so.$(MAJOR) $(prefix)/usr/lib/$(LIB_NAME).so

clean:
	$(RM) *.a *.so *.so.* *.o *.rpm 
	$(RM) *~
	$(RM) $(DEPS)

-include $(DEPS)
