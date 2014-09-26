obj-y += bitmap.o
obj-y += core_parking.o
obj-y += cpu.o
obj-y += cpupool.o
obj-$(HAS_DEVICE_TREE) += device_tree.o
obj-y += domctl.o
obj-y += domain.o
obj-y += event_2l.o
obj-y += event_channel.o
obj-y += event_fifo.o
obj-y += grant_table.o
obj-y += irq.o
obj-y += kernel.o
obj-y += keyhandler.o
obj-$(HAS_KEXEC) += kexec.o
obj-$(HAS_KEXEC) += kimage.o
obj-y += lib.o
obj-y += memory.o
obj-y += multicall.o
obj-y += notifier.o
obj-y += page_alloc.o
obj-y += preempt.o
obj-y += random.o
obj-y += rangeset.o
obj-y += sched_credit.o
obj-y += sched_credit2.o
obj-y += sched_sedf.o
obj-y += sched_arinc653.o
obj-y += sched_rt.o
obj-y += schedule.o
obj-y += shutdown.o
obj-y += softirq.o
obj-y += sort.o
obj-y += smp.o
obj-y += spinlock.o
obj-y += stop_machine.o
obj-y += string.o
obj-y += symbols.o
obj-y += sysctl.o
obj-y += tasklet.o
obj-y += time.o
obj-y += timer.o
obj-y += trace.o
obj-y += version.o
obj-y += vmap.o
obj-y += vsprintf.o
obj-y += wait.o
obj-y += xmalloc_tlsf.o
obj-y += rcupdate.o
obj-y += tmem.o
obj-y += tmem_xen.o
obj-y += radix-tree.o
obj-y += rbtree.o
obj-y += lzo.o
obj-$(HAS_PDX) += pdx.o
obj-$(HAS_MEM_ACCESS) += mem_access.o
obj-$(HAS_MEM_ACCESS) += mem_event.o

obj-bin-$(CONFIG_X86) += $(foreach n,decompress bunzip2 unxz unlzma unlzo unlz4 earlycpio,$(n).init.o)

obj-$(perfc)       += perfc.o
obj-$(crash_debug) += gdbstub.o
obj-$(xenoprof)    += xenoprof.o

obj-$(CONFIG_XENCOMM) += xencomm.o

subdir-$(CONFIG_COMPAT) += compat

subdir-$(x86_64) += hvm

subdir-$(coverage) += gcov

subdir-y += libelf
subdir-$(HAS_DEVICE_TREE) += libfdt
