obj-y += acm_ops.o
obj-y += bitmap.o
obj-y += domctl.o
obj-y += domain.o
obj-y += event_channel.o
obj-y += grant_table.o
obj-y += kernel.o
obj-y += keyhandler.o
obj-y += kexec.o
obj-y += lib.o
obj-y += memory.o
obj-y += multicall.o
obj-y += page_alloc.o
obj-y += rangeset.o
obj-y += sched_credit.o
obj-y += sched_sedf.o
obj-y += schedule.o
obj-y += shutdown.o
obj-y += softirq.o
obj-y += string.o
obj-y += symbols.o
obj-y += sysctl.o
obj-y += time.o
obj-y += timer.o
obj-y += trace.o
obj-y += version.o
obj-y += vsprintf.o
obj-y += xmalloc.o
obj-y += rcupdate.o

obj-$(perfc)       += perfc.o
obj-$(crash_debug) += gdbstub.o
obj-$(xenoprof)    += xenoprof.o

obj-$(CONFIG_XENCOMM) += xencomm.o

subdir-$(CONFIG_COMPAT) += compat

subdir-y += libelf

# Object file contains changeset and compiler information.
version.o: $(BASEDIR)/include/xen/compile.h

ifeq ($(CONFIG_COMPAT),y)
# extra dependencies
acm_ops.o: compat/acm_ops.c
grant_table.o: compat/grant_table.c
kexec.o: compat/kexec.c
schedule.o: compat/schedule.c
xenoprof.o: compat/xenoprof.c
endif
