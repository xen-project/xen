
CC       = gcc
CFLAGS   = -Wall -O3 
CFLAGS  += -I../../xen/include -I../../xenolinux-2.4.21-sparse/include

HDRS     = $(wildcard *.h)
SRCS     = $(wildcard *.c)
OBJS     = $(patsubst %.c,%.o,$(SRCS))

TARGETS  = xi_create xi_start xi_stop xi_destroy xi_build 
TARGETS += xi_phys_grant xi_phys_revoke xi_phys_probe xi_list 
TARGETS += xi_sched_global xi_sched_domain xi_usage
INSTALL  = $(TARGETS) xi_vifinit xi_helper

all: $(TARGETS)

install: all
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

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $<

