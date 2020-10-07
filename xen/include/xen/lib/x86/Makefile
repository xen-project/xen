include $(XEN_ROOT)/Config.mk

BASEDIR = $(XEN_ROOT)/xen

.PHONY: all
all: cpuid-autogen.h

cpuid-autogen.h: $(BASEDIR)/include/public/arch-x86/cpufeatureset.h $(BASEDIR)/tools/gen-cpuid.py
	$(PYTHON) $(BASEDIR)/tools/gen-cpuid.py -i $< -o $@.new
	$(call move-if-changed,$@.new,$@)
