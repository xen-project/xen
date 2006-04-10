XEN_ROOT   = ../../../..
LINUX_DIR  = linux-2.6.12-xenU
KDIR       = $(XEN_ROOT)/$(LINUX_DIR)

obj-m    += pdb.o
pdb-objs += module.o
pdb-objs += debug.o

CFLAGS += -g
CFLAGS += -Wall
CFLAGS += -Werror

.PHONY: module 
module : 
#	make KBUILD_VERBOSE=1 ARCH=xen -C $(KDIR) M=$(PWD) modules
	make                  ARCH=xen -C $(KDIR) M=$(PWD) modules

.PHONY: clean 
clean :
	make -C $(KDIR) M=$(PWD) clean

