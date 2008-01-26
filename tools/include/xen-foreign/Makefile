XEN_ROOT=../../..
include $(XEN_ROOT)/Config.mk

ROOT = $(XEN_ROOT)/xen/include/public
HOSTCFLAGS += -I$(ROOT)/foreign

MKCHECKER_PY = $(ROOT)/foreign/mkchecker.py
MKHEADER_PY = $(ROOT)/foreign/mkheader.py

architectures := x86_32 x86_64 ia64
headers := $(patsubst %, %.h, $(architectures))

.PHONY: all clean check-headers
all: $(headers) check-headers

clean:
	rm -f $(headers)
	rm -f checker checker.c
	rm -f *.pyc *.o *~

ifeq ($(CROSS_COMPILE)$(XEN_TARGET_ARCH),$(XEN_COMPILE_ARCH))
checker: checker.c $(headers)
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

check-headers: checker
	./checker > tmp.size
	diff -u $(ROOT)/foreign/reference.size tmp.size
	rm tmp.size
else
check-headers:
	@echo "cross build: skipping check"
endif

x86_32.h: $(MKHEADER_PY) $(ROOT)/arch-x86/xen-x86_32.h $(ROOT)/arch-x86/xen.h $(ROOT)/xen.h
	python $< $* $@ $(filter %.h,$^)

x86_64.h: $(MKHEADER_PY) $(ROOT)/arch-x86/xen-x86_64.h $(ROOT)/arch-x86/xen.h $(ROOT)/xen.h
	python $< $* $@ $(filter %.h,$^)

ia64.h: $(MKHEADER_PY) $(ROOT)/arch-ia64.h $(ROOT)/xen.h
	python $< $* $@ $(filter %.h,$^)

checker.c: $(MKCHECKER_PY)
	python $< $(XEN_TARGET_ARCH) $@ $(architectures)
