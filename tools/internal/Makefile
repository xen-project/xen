CC = gcc
XI_CREATE = xi_create
XI_START = xi_start
XI_STOP = xi_stop
XI_DESTROY = xi_destroy
XI_BUILD = xi_build

all: $(XI_CREATE).o $(XI_START).o $(XI_STOP).o $(XI_DESTROY).o $(XI_BUILD).o
	$(CC) -o $(XI_CREATE) $(XI_CREATE).o
	$(CC) -o $(XI_BUILD) $(XI_BUILD).o
	$(CC) -o $(XI_START) $(XI_START).o
	$(CC) -o $(XI_STOP) $(XI_STOP).o
	$(CC) -o $(XI_DESTROY) $(XI_DESTROY).o

$(XI_CREATE).o: $(XI_CREATE).c dom0_defs.h dom0_ops.h hypervisor_defs.h mem_defs.h
	$(CC) -c $(XI_CREATE).c 

internal_domain_build.o: internal_domain_build.c dom0_defs.h dom0_ops.h hypervisor_defs.h mem_defs.h
	$(CC) -c internal_domain_build.c 

$(XI_START).o: $(XI_START).c dom0_defs.h dom0_ops.h hypervisor_defs.h mem_defs.h
	$(CC) -c $(XI_START).c 

$(XI_STOP).o: $(XI_STOP).c dom0_defs.h dom0_ops.h hypervisor_defs.h mem_defs.h
	$(CC) -c $(XI_STOP).c 

$(XI_DESTROY).o: $(XI_DESTROY).c dom0_ops.h dom0_defs.h
	$(CC) -c $(XI_DESTROY).c 

install: all
	cp -a $(XI_CREATE) $(XI_BUILD) $(XI_START) $(XI_STOP) $(XI_DESTROY) ../../../install/bin

clean:
	$(RM) *.o $(XI_CREATE) $(XI_START) $(XI_STOP) $(XI_DESTROY) $(XI_BUILD)

