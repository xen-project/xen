obj-$(CONFIG_PPC64) += ppc64/

obj-$(CONFIG_EARLY_PRINTK) += early_printk.init.o
obj-y += mm-radix.o
obj-y += opal.o
obj-y += setup.o
obj-y += shutdown.o
obj-y += stubs.o
obj-y += tlb-radix.o

$(TARGET): $(TARGET)-syms
	cp -f $< $@

LAST_LINKING_PASS := 2

include scripts/Makefile.link

# Suppress orphan section checking for the time being.
orphan-handling-y :=

$(obj)/xen.lds: $(src)/xen.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

.PHONY: include
include:
