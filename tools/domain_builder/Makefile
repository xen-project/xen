CC = gcc
BUILDER = domain_builder
KILL = kill_domain

all: dom_builder.o dom_kill.o
	$(CC) -o $(BUILDER) dom_builder.o
	$(CC) -o $(KILL) dom_kill.o

install: all
	cp domain_builder kill_domain ../../../install/bin

dom_builder.o: dom_builder.c dom0_defs.h dom0_ops.h hypervisor_defs.h mem_defs.h
	$(CC) -c dom_builder.c 

dom_kill.o: dom_kill.c dom0_ops.h dom0_defs.h
	$(CC) -c dom_kill.c 

clean:
	$(RM) *.o domain_builder kill_domain

