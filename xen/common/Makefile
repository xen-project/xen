include $(BASEDIR)/Rules.mk

obj-y += acm_ops.o
obj-y += bitmap.o
obj-y += dom0_ops.o
obj-y += domain.o
obj-y += elf.o
obj-y += event_channel.o
obj-y += grant_table.o
obj-y += kernel.o
obj-y += keyhandler.o
obj-y += lib.o
obj-y += memory.o
obj-y += multicall.o
obj-y += page_alloc.o
obj-y += rangeset.o
obj-y += sched_bvt.o
obj-y += sched_sedf.o
obj-y += schedule.o
obj-y += softirq.o
obj-y += string.o
obj-y += symbols.o
obj-y += trace.o
obj-y += timer.o
obj-y += vsprintf.o
obj-y += xmalloc.o

obj-$(perfc)       += perfc.o
obj-$(crash_debug) += gdbstub.o

include $(BASEDIR)/Post.mk

# Object file contains changeset and compiler information.
kernel.o: $(BASEDIR)/include/xen/compile.h
