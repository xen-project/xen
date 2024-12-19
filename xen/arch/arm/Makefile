obj-$(CONFIG_ARM_32) += arm32/
obj-$(CONFIG_ARM_64) += arm64/
obj-$(CONFIG_MMU) += mmu/
obj-$(CONFIG_ACPI) += acpi/
obj-$(CONFIG_HAS_PCI) += pci/
ifneq ($(CONFIG_NO_PLAT),y)
obj-y += platforms/
endif
obj-y += firmware/
obj-$(CONFIG_TEE) += tee/
obj-$(CONFIG_HAS_VPCI) += vpci.o

obj-$(CONFIG_HAS_ALTERNATIVE) += alternative.o
obj-y += cpuerrata.o
obj-y += cpufeature.o
obj-y += decode.o
obj-y += device.o
obj-$(CONFIG_IOREQ_SERVER) += dm.o
obj-$(CONFIG_DOM0LESS_BOOT) += dom0less-build.init.o
obj-y += domain.o
obj-y += domain_build.init.o
obj-y += domctl.o
obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
obj-y += efi/
obj-y += gic.o
obj-$(CONFIG_GICV2) += gic-v2.o
obj-$(CONFIG_GICV3) += gic-v3.o
obj-$(CONFIG_HAS_ITS) += gic-v3-its.o
obj-$(CONFIG_HAS_ITS) += gic-v3-lpi.o
obj-y += guestcopy.o
obj-y += guest_atomics.o
obj-y += guest_walk.o
obj-y += hvm.o
obj-y += io.o
obj-$(CONFIG_IOREQ_SERVER) += ioreq.o
obj-y += irq.o
obj-y += kernel.init.o
obj-$(CONFIG_LIVEPATCH) += livepatch.o
obj-$(CONFIG_LLC_COLORING) += llc-coloring.o
obj-$(CONFIG_MEM_ACCESS) += mem_access.o
obj-y += mm.o
obj-y += monitor.o
obj-y += p2m.o
obj-y += platform.o
obj-y += platform_hypercall.o
obj-y += physdev.o
obj-y += processor.o
obj-y += psci.o
obj-y += setup.o
obj-y += shutdown.o
obj-y += smp.o
obj-y += smpboot.o
obj-$(CONFIG_STATIC_EVTCHN) += static-evtchn.init.o
obj-$(CONFIG_STATIC_MEMORY) += static-memory.init.o
obj-$(CONFIG_STATIC_SHM) += static-shmem.init.o
obj-y += sysctl.o
obj-y += time.o
obj-y += traps.o
obj-y += vcpreg.o
obj-$(CONFIG_NEW_VGIC) += vgic/
ifneq ($(CONFIG_NEW_VGIC),y)
obj-y += gic-vgic.o
obj-y += vgic.o
obj-$(CONFIG_VGICV2) += vgic-v2.o
obj-$(CONFIG_GICV3) += vgic-v3.o
obj-$(CONFIG_HAS_ITS) += vgic-v3-its.o
endif
obj-y += vm_event.o
obj-y += vtimer.o
obj-$(CONFIG_SBSA_VUART_CONSOLE) += vpl011.o
obj-y += vsmc.o
obj-y += vpsci.o
obj-$(CONFIG_HWDOM_VUART) += vuart.o

extra-y += xen.lds

#obj-bin-y += ....o

ifneq ($(CONFIG_DTB_FILE),"")
obj-y += dtb.o
endif

ifdef CONFIG_LIVEPATCH
all_symbols = --all-symbols
ifdef CONFIG_FAST_SYMBOL_LOOKUP
all_symbols = --all-symbols --sort-by-name
endif
else
all_symbols =
endif

$(TARGET): $(TARGET)-syms
	$(OBJCOPY) -O binary -S $< $@
ifeq ($(CONFIG_ARM_64),y)
	ln -sf $(@F) $@.efi
endif

$(TARGET)-syms: $(objtree)/prelink.o $(obj)/xen.lds
	$(LD) $(XEN_LDFLAGS) -T $(obj)/xen.lds -N $< \
	    $(objtree)/common/symbols-dummy.o -o $(dot-target).0
	$(NM) -pa --format=sysv $(dot-target).0 \
		| $(objtree)/tools/symbols $(all_symbols) --sysv --sort \
		> $(dot-target).0.S
	$(MAKE) $(build)=$(@D) $(dot-target).0.o
	$(LD) $(XEN_LDFLAGS) -T $(obj)/xen.lds -N $< \
	    $(dot-target).0.o -o $(dot-target).1
	$(NM) -pa --format=sysv $(dot-target).1 \
		| $(objtree)/tools/symbols $(all_symbols) --sysv --sort \
		> $(dot-target).1.S
	$(MAKE) $(build)=$(@D) $(dot-target).1.o
	$(LD) $(XEN_LDFLAGS) -T $(obj)/xen.lds -N $< $(build_id_linker) \
	    $(dot-target).1.o -o $@
	$(NM) -pa --format=sysv $@ \
		| $(objtree)/tools/symbols --all-symbols --xensyms --sysv --sort \
		> $@.map
	rm -f $(@D)/.$(@F).[0-9]*

.PHONY: include
include:

$(obj)/xen.lds: $(src)/xen.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

$(obj)/dtb.o: $(patsubst "%",%,$(CONFIG_DTB_FILE))

clean-files := $(objtree)/.xen-syms.[0-9]*
