obj-y += aia.o
obj-y += aplic.o
obj-y += cpufeature.o
obj-y += domain.o
obj-y += domain-build.init.o
obj-$(CONFIG_DOM0LESS_BOOT) += dom0less-build.init.o
obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
obj-y += entry.o
obj-y += extable.o
obj-y += guestcopy.o
obj-y += imsic.o
obj-y += intc.o
obj-y += irq.o
obj-y += kernel.init.o
obj-y += mm.o
obj-y += p2m.o
obj-y += paging.o
obj-y += pt.o
obj-$(CONFIG_RISCV_64) += riscv64/
obj-y += sbi.o
obj-y += setup.init.o
obj-y += shutdown.o
obj-y += smp.o
obj-y += smpboot.o
obj-y += stubs.o
obj-y += time.o
obj-y += traps.o
obj-y += vaplic.o
obj-y += vmid.o
obj-y += vm_event.o
obj-y += vsbi/
obj-y += vtimer.o

$(TARGET): $(TARGET)-syms
	$(OBJCOPY) -O binary -S $< $@

LAST_LINKING_PASS := 3

include scripts/Makefile.link

# Suppress orphan section checking for the time being.
orphan-handling-y :=

$(obj)/xen.lds: $(src)/xen.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

.PHONY: include
include:
