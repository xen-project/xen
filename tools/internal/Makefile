
CC       = gcc
CFLAGS   = -Wall -O3 
CFLAGS  += -I../../xen/include -I../../xenolinux-sparse/include

HDRS     = $(wildcard *.h)
SRCS     = $(wildcard *.c)
OBJS     = $(patsubst %.c,%.o,$(SRCS))

TARGETS  = xi_create xi_start xi_stop xi_destroy xi_build 
TARGETS += xi_phys_grant xi_list xi_save_linux xi_restore_linux
TARGETS += xi_sched_global xi_sched_domain xi_usage xi_vif_params
TARGETS += xi_vbd_create xi_vbd_add xi_vbd_list xi_vbd_info 
INSTALL  = $(TARGETS) xi_vifinit xi_helper

all: check-for-zlib $(TARGETS)

check-for-zlib:
	@if [ ! -e /usr/include/zlib.h ]; then \
	echo "***********************************************************"; \
	echo "ERROR: install zlib header files (http://www.gzip.org/zlib)"; \
	echo "***********************************************************"; \
	false; \
	fi

install: all
	mkdir -p ../../../install/bin
	cp -a $(INSTALL) ../../../install/bin
	chmod 755 ../../../install/bin/xi_vifinit
	chmod 755 ../../../install/bin/xi_helper

clean:
	$(RM) *.o *.rpm $(TARGETS)

rpm: all
	rm -rf staging
	mkdir staging
	mkdir staging/i386
	rpmbuild --define "staging$$PWD/staging" --define '_builddir.' --define "_rpmdir$$PWD/staging" -bb rpm.spec
	mv staging/i386/*.rpm .
	rm -rf staging

xi_build xi_save_linux xi_restore_linux: %: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -lz -o $@ $<

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $<

