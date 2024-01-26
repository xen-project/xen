obj-$(CONFIG_PV32) += compat/

obj-bin-y += entry.o
obj-y += traps.o
obj-$(CONFIG_KEXEC) += machine_kexec.o
obj-y += pci.o
obj-y += acpi_mmcfg.o
obj-y += mmconf-fam10h.o
obj-y += mmconfig_64.o
obj-y += mmconfig-shared.o
obj-$(CONFIG_COMPAT) += domain.o
obj-$(CONFIG_COMPAT) += cpu_idle.o
obj-$(CONFIG_COMPAT) += cpufreq.o
obj-bin-$(CONFIG_KEXEC) += kexec_reloc.o
