subdir-y += tables
subdir-y += utilities
subdir-$(CONFIG_X86) += apei

obj-bin-y += tables.init.o
obj-$(CONFIG_NUMA) += numa.o
obj-y += osl.o
obj-$(CONFIG_HAS_CPUFREQ) += pmstat.o

obj-$(CONFIG_X86) += hwregs.o
obj-$(CONFIG_X86) += reboot.o
