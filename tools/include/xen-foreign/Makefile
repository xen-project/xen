XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

ROOT = $(XEN_ROOT)/xen/include/public

architectures := arm32 arm64 x86_32 x86_64
headers := $(patsubst %, %.h, $(architectures))

.PHONY: all clean distclean check-headers
all: $(headers) check-headers

clean:
	rm -f $(headers)
	rm -f checker checker.c
	rm -f *.pyc *.o *~

distclean: clean

checker: checker.c $(headers)
	$(HOSTCC) $(HOSTCFLAGS) -D__XEN_TOOLS__ -o $@ $<

check-headers: checker
	./checker > tmp.size
	diff -u reference.size tmp.size
	rm tmp.size

arm32.h: mkheader.py structs.py $(ROOT)/arch-arm.h $(ROOT)/xen.h
	$(PYTHON) $< $* $@.tmp $(filter %.h,$^)
	#Avoid mixing an alignment directive with a uint64_t cast or sizeof expression
	sed 's/(__align8__ \(uint64_t\))/(\1)/g' < $@.tmp > $@.tmp2
	rm $@.tmp
	$(call move-if-changed,$@.tmp2,$@)

arm64.h: mkheader.py structs.py $(ROOT)/arch-arm.h $(ROOT)/xen.h
	$(PYTHON) $< $* $@.tmp $(filter %.h,$^)
	#Avoid mixing an alignment directive with a uint64_t cast or sizeof expression
	sed 's/(__align8__ \(uint64_t\))/(\1)/g' < $@.tmp > $@.tmp2
	rm $@.tmp
	$(call move-if-changed,$@.tmp2,$@)

x86_32.h: mkheader.py structs.py $(ROOT)/arch-x86/xen-x86_32.h $(ROOT)/arch-x86/xen.h $(ROOT)/xen.h
	$(PYTHON) $< $* $@.tmp $(filter %.h,$^)
	#Avoid mixing an alignment directive with a uint64_t cast or sizeof expression
	sed 's/(__align8__ \(uint64_t\))/(\1)/g' < $@.tmp > $@.tmp2
	rm $@.tmp
	$(call move-if-changed,$@.tmp2,$@)

x86_64.h: mkheader.py structs.py $(ROOT)/arch-x86/xen-x86_64.h $(ROOT)/arch-x86/xen.h $(ROOT)/xen.h
	$(PYTHON) $< $* $@.tmp $(filter %.h,$^)
	#Avoid mixing an alignment directive with a uint64_t cast or sizeof expression
	sed 's/(__align8__ \(uint64_t\))/(\1)/g' < $@.tmp > $@.tmp2
	rm $@.tmp
	$(call move-if-changed,$@.tmp2,$@)

checker.c: mkchecker.py structs.py
	$(PYTHON) $< $@ $(architectures)
