
MAJOR    = 1.3
MINOR    = 0
SONAME   = libxc.so.$(MAJOR)

CC       = gcc

XEN_ROOT = ../../..

vpath %.h      $(XEN_ROOT)/xen/include/hypervisor-ifs
INCLUDES += -I $(XEN_ROOT)/xen/include/hypervisor-ifs

vpath %.h      $(XEN_ROOT)/tools/xu/lib
INCLUDES += -I $(XEN_ROOT)/tools/xu/lib

vpath %h       $(XEN_ROOT)/linux-xen-sparse/include
INCLUDES += -I $(XEN_ROOT)/linux-xen-sparse/include

vpath %c       $(XEN_ROOT)/tools/lib
INCLUDES += -I $(XEN_ROOT)/tools/lib

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

SRCS     :=
SRCS     += xc_atropos.c
SRCS     += xc_bvtsched.c
SRCS     += xc_domain.c
SRCS     += xc_evtchn.c
SRCS     += xc_io.c
SRCS     += xc_linux_build.c
SRCS     += xc_linux_restore.c
SRCS     += xc_linux_save.c
SRCS     += xc_misc.c
SRCS     += xc_netbsd_build.c
SRCS     += xc_physdev.c
SRCS     += xc_private.c
SRCS     += $(LIB_SRCS)

#CFLAGS  += -I../../../xen/include/hypervisor-ifs
#CFLAGS  += -I../../xu/lib
#CFLAGS  += -I../../../linux-xen-sparse/include

CFLAGS   += -Wall
CFLAGS   += -Werror
CFLAGS   += -g
CFLAGS   += -O3
CFLAGS   += -fno-strict-aliasing
CFLAGS   += $(INCLUDES)
# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

OBJS     = $(patsubst %.c,%.o,$(SRCS))

LIB      = libxc.so libxc.so.$(MAJOR) libxc.so.$(MAJOR).$(MINOR)

all: check-for-zlib $(LIB)

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
	install -m0644 xc.h $(prefix)/usr/include

clean:
	$(RM) *.a *.so *.o *.rpm $(LIB)
	$(RM) *~
	$(RM) $(DEPS)

rpm: all
	rm -rf staging
	mkdir staging
	mkdir staging/i386
	rpmbuild --define "staging$$PWD/staging" --define '_builddir.' \
		--define "_rpmdir$$PWD/staging" -bb rpm.spec
	mv staging/i386/*.rpm .
	rm -rf staging

libxc.so:
	ln -sf libxc.so.$(MAJOR) $@
libxc.so.$(MAJOR):
	ln -sf libxc.so.$(MAJOR).$(MINOR) $@
libxc.so.$(MAJOR).$(MINOR): $(OBJS)
	$(CC) -Wl,-soname -Wl,$(SONAME) -shared -o $@ $^ -lz

%.o: %.c Makefile

#	$(CC) $(CFLAGS) -o $@ $<

-include $(DEPS)
