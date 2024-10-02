obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
obj-y += entry.o
obj-y += mm.o
obj-y += pt.o
obj-$(CONFIG_RISCV_64) += riscv64/
obj-y += sbi.o
obj-y += setup.o
obj-y += shutdown.o
obj-y += smp.o
obj-y += stubs.o
obj-y += traps.o
obj-y += vm_event.o

$(TARGET): $(TARGET)-syms
	$(OBJCOPY) -O binary -S $< $@

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

$(obj)/xen.lds: $(src)/xen.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

.PHONY: include
include:
