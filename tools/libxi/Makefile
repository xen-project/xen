
CC       = gcc
CFLAGS   = -c -Wall -O3 
CFLAGS  += -I../../xen/include -I../../xenolinux-sparse/include

HDRS     = $(wildcard *.h)
OBJS     = $(patsubst %.c,%.o,$(wildcard libxi_*.c))

LIBS     = libxi.a libxi.so

all: check-for-zlib $(LIBS)
	ranlib libxi.a

check-for-zlib:
	@if [ ! -e /usr/include/zlib.h ]; then \
	echo "***********************************************************"; \
	echo "ERROR: install zlib header files (http://www.gzip.org/zlib)"; \
	echo "***********************************************************"; \
	false; \
	fi

install: all
	mkdir -p ../../../install/lib
	mkdir -p ../../../install/include
	cp -a $(LIBS) ../../../install/lib
	for i in $(LIBS) do ; chmod 755 ../../../install/bin/$i ; done
	cp -a xi.h ../../../install/include
	chmod 644 ../../../install/include/xi.h

clean:
	$(RM) *.a *.so *.o *.rpm $(LIBS)

rpm: all
	rm -rf staging
	mkdir staging
	mkdir staging/i386
	rpmbuild --define "staging$$PWD/staging" --define '_builddir.' \
		--define "_rpmdir$$PWD/staging" -bb rpm.spec
	mv staging/i386/*.rpm .
	rm -rf staging

libxi.so: $(OBJS)
	$(LD) -shared -o $@ $^ -lz

libxi.a: libxi.a($(OBJS))

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $<
