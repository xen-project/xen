include $(XEN_ROOT)/Config.mk

.PHONY: all
all: cpuid-autogen.h

cpuid-autogen.h: $(XEN_ROOT)/xen/include/public/arch-x86/cpufeatureset.h $(XEN_ROOT)/xen/tools/gen-cpuid.py
	$(PYTHON) $(XEN_ROOT)/xen/tools/gen-cpuid.py -i $< -o $@.new
	$(call move-if-changed,$@.new,$@)
