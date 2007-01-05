obj-y += entry.o
obj-y += gpr_switch.o
obj-y += mm.o
obj-y += traps.o

ifeq ($(CONFIG_COMPAT),y)
# extra dependencies
entry.o:	compat/entry.S
traps.o:	compat/traps.c
endif
