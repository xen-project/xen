obj-$(CONFIG_PV) += compat/

obj-bin-y += entry.o
obj-y += traps.o
obj-$(CONFIG_KEXEC) += machine_kexec.o
obj-y += pci.o
obj-y += acpi_mmcfg.o
obj-y += mmconf-fam10h.o
obj-y += mmconfig_64.o
obj-y += mmconfig-shared.o
obj-y += domain.o
obj-y += cpu_idle.o
obj-y += cpufreq.o
obj-bin-$(CONFIG_KEXEC) += kexec_reloc.o

obj-$(CONFIG_CRASH_DEBUG)   += gdbstub.o
