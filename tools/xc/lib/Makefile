
MAJOR    = 1.3
MINOR    = 0
SONAME   = libxc.so.$(MAJOR)

CC       = gcc
CFLAGS   = -c -Wall -O3 
CFLAGS  += -I../../../xen/include -I../../../xenolinux-sparse/include

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard *.c))

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
	cp -a $(LIB) $(prefix)/usr/lib
	chmod 755 $(prefix)/usr/lib/$(LIB)
	cp xc.h $(prefix)/usr/include
	chmod 644 $(prefix)/usr/include/xc.h

dist: all
	mkdir -p ../../../../install/lib
	mkdir -p ../../../../install/include
	cp -a $(LIB) ../../../../install/lib
	chmod 755 ../../../../install/lib/$(LIB)
	cp xc.h ../../../../install/include
	chmod 644 ../../../../install/include/xc.h

clean:
	$(RM) *.a *.so *.o *.rpm $(LIB)

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

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $<
