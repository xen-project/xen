subdir-y += compat

obj-y += entry.o
obj-y += gpr_switch.o
obj-y += mm.o
obj-y += traps.o
obj-y += machine_kexec.o
obj-y += pci.o
obj-y += acpi_mmcfg.o
obj-y += mmconfig_64.o
obj-y += mmconfig-shared.o

obj-$(crash_debug)   += gdbstub.o
obj-$(CONFIG_COMPAT) += compat.o
obj-$(CONFIG_COMPAT) += compat_kexec.o
obj-$(CONFIG_COMPAT) += domain.o
obj-$(CONFIG_COMPAT) += physdev.o
obj-$(CONFIG_COMPAT) += platform_hypercall.o
obj-$(CONFIG_COMPAT) += cpu_idle.o
obj-$(CONFIG_COMPAT) += cpufreq.o
