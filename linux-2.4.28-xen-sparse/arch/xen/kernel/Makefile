
.S.o:
	$(CC) $(AFLAGS) -traditional -c $< -o $*.o

all: kernel.o head.o init_task.o

O_TARGET := kernel.o

export-objs     := i386_ksyms.o gnttab.o skbuff.o ctrl_if.o

obj-y	:= process.o semaphore.o signal.o entry.o traps.o irq.o  \
		ptrace.o ioport.o ldt.o setup.o time.o sys_i386.o \
		i386_ksyms.o i387.o evtchn.o ctrl_if.o pci-dma.o \
		reboot.o fixup.o gnttab.o skbuff.o

ifdef CONFIG_PCI
obj-y	+= pci-i386.o pci-pc.o
endif

include $(TOPDIR)/Rules.make
