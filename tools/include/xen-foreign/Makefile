XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

ROOT = $(XEN_ROOT)/xen/include/public

architectures := arm32 arm64 x86_32 x86_64
headers := $(patsubst %, %.h, $(architectures))

.PHONY: all clean check-headers
all: $(headers) check-headers

clean:
	rm -f $(headers)
	rm -f checker checker.c
	rm -f *.pyc *.o *~

checker: checker.c $(headers)
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

check-headers: checker
	./checker > tmp.size
	diff -u reference.size tmp.size
	rm tmp.size

arm32.h: mkheader.py structs.py $(ROOT)/arch-arm.h $(ROOT)/xen.h
	$(PYTHON) $< $* $@ $(filter %.h,$^)

arm64.h: mkheader.py structs.py $(ROOT)/arch-arm.h $(ROOT)/xen.h
	$(PYTHON) $< $* $@ $(filter %.h,$^)

x86_32.h: mkheader.py structs.py $(ROOT)/arch-x86/xen-x86_32.h $(ROOT)/arch-x86/xen.h $(ROOT)/xen.h
	$(PYTHON) $< $* $@ $(filter %.h,$^)

x86_64.h: mkheader.py structs.py $(ROOT)/arch-x86/xen-x86_64.h $(ROOT)/arch-x86/xen.h $(ROOT)/xen.h
	$(PYTHON) $< $* $@ $(filter %.h,$^)

checker.c: mkchecker.py structs.py
	$(PYTHON) $< $@ $(architectures)
