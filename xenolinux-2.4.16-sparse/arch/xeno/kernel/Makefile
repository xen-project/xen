
.S.o:
	$(CC) $(AFLAGS) -traditional -c $< -o $*.o

all: kernel.o head.o init_task.o

O_TARGET := kernel.o

export-objs := i386_ksyms.o

obj-y := process.o semaphore.o signal.o entry.o traps.o irq.o \
	ptrace.o ioport.o ldt.o setup.o time.o sys_i386.o \
	i386_ksyms.o i387.o hypervisor.o

include $(TOPDIR)/Rules.make
