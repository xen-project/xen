CC = gcc
CFLAGS = -Wall -I../../xen/include
XI_CREATE = xi_create
XI_START = xi_start
XI_STOP = xi_stop
XI_DESTROY = xi_destroy
XI_BUILD = xi_build
XI_PHYS_GRANT = xi_phys_grant
XI_PHYS_REVOKE = xi_phys_revoke
XI_PHYS_PROBE = xi_phys_probe

all: $(XI_CREATE).o $(XI_START).o $(XI_STOP).o $(XI_DESTROY).o $(XI_BUILD).o \
	$(XI_PHYS_GRANT).o $(XI_PHYS_REVOKE).o $(XI_PHYS_PROBE).o
	$(CC) -o $(XI_CREATE) $(XI_CREATE).o
	$(CC) -o $(XI_BUILD) $(XI_BUILD).o
	$(CC) -o $(XI_START) $(XI_START).o
	$(CC) -o $(XI_STOP) $(XI_STOP).o
	$(CC) -o $(XI_DESTROY) $(XI_DESTROY).o
	$(CC) -o $(XI_PHYS_GRANT) $(XI_PHYS_GRANT).o
	$(CC) -o $(XI_PHYS_REVOKE) $(XI_PHYS_REVOKE).o
	$(CC) -o $(XI_PHYS_PROBE) $(XI_PHYS_PROBE).o

$(XI_CREATE).o: $(XI_CREATE).c dom0_defs.h dom0_ops.h mem_defs.h
	$(CC) $(CFLAGS) -c $(XI_CREATE).c 

internal_domain_build.o: internal_domain_build.c dom0_defs.h dom0_ops.h mem_defs.h
	$(CC) $(CFLAGS) -c internal_domain_build.c 

$(XI_START).o: $(XI_START).c dom0_defs.h dom0_ops.h mem_defs.h
	$(CC) $(CFLAGS) -c $(XI_START).c 

$(XI_STOP).o: $(XI_STOP).c dom0_defs.h dom0_ops.h mem_defs.h
	$(CC) $(CFLAGS) -c $(XI_STOP).c 

$(XI_DESTROY).o: $(XI_DESTROY).c dom0_ops.h dom0_defs.h
	$(CC) $(CFLAGS) -c $(XI_DESTROY).c 

$(XI_PHYS_GRANT).o: $(XI_PHYS_GRANT).c 
	$(CC) $(CFLAGS) -c $(XI_PHYS_GRANT).c 

$(XI_PHYS_REVOKE).o: $(XI_PHYS_REVOKE).c
	$(CC) $(CFLAGS) -c $(XI_PHYS_REVOKE).c 

$(XI_PHYS_PROBE).o: $(XI_PHYS_PROBE).c
	$(CC) $(CFLAGS) -c $(XI_PHYS_PROBE).c 

install: all
	cp -a xi_list xi_vifinit xi_helper $(XI_CREATE) $(XI_BUILD) $(XI_START) $(XI_STOP) $(XI_DESTROY) $(XI_PHYSDEV_GRANT) $(XI_PHYS_REVOKE) $(XI_PHYS_PROBE).o../../../install/bin
	chmod 755 ../../../install/bin/xi_list
	chmod 755 ../../../install/bin/xi_vifinit
	chmod 755 ../../../install/bin/xi_helper

rpm: all
	rm -rf staging
	mkdir staging
	mkdir staging/i386
	rpmbuild --define "staging$$PWD/staging" --define '_builddir.' --define "_rpmdir$$PWD/staging" -bb rpm.spec
	mv staging/i386/*.rpm .
	rm -rf staging

clean:
	$(RM) *.o *.rpm $(XI_CREATE) $(XI_START) $(XI_STOP) $(XI_DESTROY) $(XI_BUILD) $(XI_PHYS_GRANT) $(XI_PHYS_REVOKE) $(XI_PHYS_PROBE)

