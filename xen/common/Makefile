obj-$(CONFIG_ARGO) += argo.o
obj-y += bitmap.o
obj-bin-$(CONFIG_SELF_TESTS) += bitops.init.o
obj-$(CONFIG_GENERIC_BUG_FRAME) += bug.o
obj-$(CONFIG_HYPFS_CONFIG) += config_data.o
obj-$(CONFIG_CORE_PARKING) += core_parking.o
obj-y += cpu.o
obj-$(CONFIG_DEBUG_TRACE) += debugtrace.o
obj-$(CONFIG_HAS_DEVICE_TREE) += device.o
obj-$(filter-out $(CONFIG_X86),$(CONFIG_ACPI)) += device.o
obj-$(CONFIG_HAS_DEVICE_TREE) += device-tree/
obj-$(CONFIG_IOREQ_SERVER) += dm.o
obj-y += domain.o
obj-y += event_2l.o
obj-y += event_channel.o
obj-y += event_fifo.o
obj-$(CONFIG_GRANT_TABLE) += grant_table.o
obj-y += guestcopy.o
obj-y += gzip/
obj-$(CONFIG_HYPFS) += hypfs.o
obj-$(CONFIG_IOREQ_SERVER) += ioreq.o
obj-y += irq.o
obj-y += kernel.o
obj-y += keyhandler.o
obj-$(CONFIG_KEXEC) += kexec.o
obj-$(CONFIG_KEXEC) += kimage.o
obj-$(CONFIG_LIVEPATCH) += livepatch.o livepatch_elf.o
obj-$(CONFIG_LLC_COLORING) += llc-coloring.o
obj-$(CONFIG_MEM_ACCESS) += mem_access.o
obj-y += memory.o
obj-y += multicall.o
obj-y += notifier.o
obj-$(CONFIG_NUMA) += numa.o
obj-y += page_alloc.o
obj-y += pdx.o
obj-y += percpu.o
obj-$(CONFIG_PERF_COUNTERS) += perfc.o
obj-bin-$(CONFIG_HAS_PMAP) += pmap.init.o
obj-y += preempt.o
obj-y += random.o
obj-y += rangeset.o
obj-y += radix-tree.o
obj-y += rcupdate.o
obj-y += rwlock.o
obj-y += shutdown.o
obj-y += softirq.o
obj-y += smp.o
obj-y += spinlock.o
obj-y += stop_machine.o
obj-y += symbols.o
obj-y += tasklet.o
obj-y += time.o
obj-y += timer.o
obj-$(CONFIG_TRACEBUFFER) += trace.o
obj-y += version.o
obj-y += virtual_region.o
obj-y += vm_event.o
obj-$(CONFIG_HAS_VMAP) += vmap.o
obj-y += vsprintf.o
obj-y += wait.o
obj-bin-y += warning.init.o
obj-$(CONFIG_XENOPROF) += xenoprof.o
obj-y += xmalloc_tlsf.o

obj-bin-$(CONFIG_X86) += $(foreach n,decompress bunzip2 unxz unlzma lzo unlzo unlz4 unzstd earlycpio,$(n).init.o)

obj-$(CONFIG_COMPAT) += $(addprefix compat/,domain.o memory.o multicall.o xlat.o)

ifneq ($(CONFIG_PV_SHIM_EXCLUSIVE),y)
obj-y += domctl.o
obj-y += monitor.o
obj-y += sysctl.o
endif

extra-y := symbols-dummy.o

obj-$(CONFIG_COVERAGE) += coverage/
obj-y += sched/
obj-$(CONFIG_UBSAN) += ubsan/

obj-$(CONFIG_NEEDS_LIBELF) += libelf/
obj-$(CONFIG_HAS_DEVICE_TREE) += libfdt/

CONF_FILE := $(if $(patsubst /%,,$(KCONFIG_CONFIG)),$(objtree)/)$(KCONFIG_CONFIG)
$(obj)/config.gz: $(CONF_FILE)
	gzip -n -c $< >$@

$(obj)/config_data.o: $(obj)/config.gz

$(obj)/config_data.S: $(srctree)/tools/binfile FORCE
	$(call if_changed,binfile,$(obj)/config.gz xen_config_data)
targets += config_data.S

clean-files := config.gz
