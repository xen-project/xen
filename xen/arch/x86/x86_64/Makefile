subdir-y += compat

obj-y += entry.o
obj-y += compat_kexec.o
obj-y += gpr_switch.o
obj-y += mm.o
obj-y += traps.o

obj-$(CONFIG_COMPAT) += compat.o
obj-$(CONFIG_COMPAT) += domain.o
obj-$(CONFIG_COMPAT) += physdev.o
obj-$(CONFIG_COMPAT) += platform_hypercall.o

ifeq ($(CONFIG_COMPAT),y)
# extra dependencies
compat.o:	../compat.c
domctl.o:	../domctl.c
mm.o:		compat/mm.c
physdev.o:	../physdev.c
platform_hypercall.o: ../platform_hypercall.c
sysctl.o:	../sysctl.c
traps.o:	compat/traps.c
endif
