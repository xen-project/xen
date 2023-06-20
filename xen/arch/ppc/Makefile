obj-$(CONFIG_PPC64) += ppc64/

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
