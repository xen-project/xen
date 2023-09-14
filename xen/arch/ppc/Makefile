obj-$(CONFIG_PPC64) += ppc64/

obj-$(CONFIG_EARLY_PRINTK) += early_printk.init.o
obj-y += mm-radix.o
obj-y += opal.o
obj-y += setup.o
obj-y += stubs.o
obj-y += tlb-radix.o

$(TARGET): $(TARGET)-syms
	cp -f $< $@

$(TARGET)-syms: $(objtree)/prelink.o $(obj)/xen.lds
	$(LD) $(XEN_LDFLAGS) -T $(obj)/xen.lds -N $< $(build_id_linker) -o $@
	$(NM) -pa --format=sysv $@ \
		| $(objtree)/tools/symbols --all-symbols --xensyms --sysv --sort \
		> $@.map

$(obj)/xen.lds: $(src)/xen.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

.PHONY: include
include:
