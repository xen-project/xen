subdir-y += tables
subdir-y += utilities
subdir-$(x86) += apei

obj-bin-y += tables.init.o
obj-$(HAS_NUMA) += numa.o
obj-y += osl.o
obj-y += pmstat.o

obj-$(x86) += hwregs.o
obj-$(x86) += reboot.o
