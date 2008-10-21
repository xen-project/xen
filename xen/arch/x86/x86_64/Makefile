subdir-y += compat

obj-y += entry.o
obj-y += gpr_switch.o
obj-y += mm.o
obj-y += traps.o
obj-y += machine_kexec.o

obj-$(crash_debug)   += gdbstub.o
obj-$(CONFIG_COMPAT) += compat.o
obj-$(CONFIG_COMPAT) += compat_kexec.o
obj-$(CONFIG_COMPAT) += domain.o
obj-$(CONFIG_COMPAT) += physdev.o
obj-$(CONFIG_COMPAT) += platform_hypercall.o
obj-$(CONFIG_COMPAT) += cpu_idle.o
obj-$(CONFIG_COMPAT) += cpufreq.o

ifeq ($(CONFIG_COMPAT),y)
# extra dependencies
compat.o:	../compat.c
domctl.o:	../domctl.c
mm.o:		compat/mm.c
physdev.o:	../physdev.c
platform_hypercall.o: ../platform_hypercall.c
sysctl.o:	../sysctl.c
traps.o:	compat/traps.c
cpu_idle.o:	../acpi/cpu_idle.c
cpufreq.o:	../../../drivers/cpufreq/cpufreq.c
endif
