obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
obj-y += entry.o
obj-y += mm.o
obj-$(CONFIG_RISCV_64) += riscv64/
obj-y += sbi.o
obj-y += setup.o
obj-y += traps.o

$(TARGET): $(TARGET)-syms
	$(OBJCOPY) -O binary -S $< $@

$(TARGET)-syms: $(objtree)/prelink.o $(obj)/xen.lds
	$(LD) $(XEN_LDFLAGS) -T $(obj)/xen.lds -N $< $(build_id_linker) -o $@
	$(NM) -pa --format=sysv $@ \
		| $(objtree)/tools/symbols --all-symbols --xensyms --sysv --sort \
		> $@.map

$(obj)/xen.lds: $(src)/xen.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

.PHONY: include
include:
