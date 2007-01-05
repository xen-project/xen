obj-y += entry.o
obj-y += gpr_switch.o
obj-y += mm.o
obj-y += traps.o

obj-$(CONFIG_COMPAT) += compat.o
obj-$(CONFIG_COMPAT) += physdev.o

ifeq ($(CONFIG_COMPAT),y)
# extra dependencies
compat.o:	../compat.c
entry.o:	compat/entry.S
mm.o:		compat/mm.c
physdev.o:	../physdev.c
traps.o:	compat/traps.c
endif
