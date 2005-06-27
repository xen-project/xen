XEN_ROOT=/anfs/nos1/ach61/bk
KDIR=$(XEN_ROOT)/linux-2.6.11-xenU

obj-m    += pdb.o
pdb-objs += module.o
pdb-objs += debug.o

CFLAGS += -g
CFLAGS += -Wall
CFLAGS += -Werror

module : 
#	make KBUILD_VERBOSE=1 ARCH=xen -C $(KDIR) M=$(PWD) modules
	make                  ARCH=xen -C $(KDIR) M=$(PWD) modules

clean :
	make -C $(KDIR) M=$(PWD) clean

