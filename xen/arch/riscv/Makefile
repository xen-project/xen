obj-$(CONFIG_RISCV_64) += riscv64/
obj-y += sbi.o
obj-y += setup.o

$(TARGET): $(TARGET)-syms
	$(OBJCOPY) -O binary -S $< $@

$(TARGET)-syms: $(objtree)/prelink.o $(obj)/xen.lds
	$(LD) $(XEN_LDFLAGS) -T $(obj)/xen.lds -N $< $(build_id_linker) -o $@
	$(NM) -pa --format=sysv $(@D)/$(@F) \
		| $(objtree)/tools/symbols --all-symbols --xensyms --sysv --sort \
		>$(@D)/$(@F).map

$(obj)/xen.lds: $(src)/xen.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

.PHONY: include
include:
