XEN_ROOT=../../..
include $(XEN_ROOT)/Config.mk

ROOT = $(XEN_ROOT)/xen/include/public/foreign
HOSTCFLAGS += -I$(ROOT)

MKHEADER_PY = $(ROOT)/mkheader.py

architectures := x86_32 x86_64 ia64
headers := $(patsubst %, %.h, $(architectures))
scripts := $(wildcard *.py)

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
	diff -u $(ROOT)/reference.size tmp.size
	rm tmp.size
else
check-headers:
	@echo "cross build: skipping check"
endif

x86_32.h: $(ROOT)/mkheader.py ../xen/arch-x86/xen-x86_32.h ../xen/arch-x86/xen.h ../xen/xen.h
	python $< $* $@ $(filter %.h,$^)

x86_64.h: $(ROOT)/mkheader.py ../xen/arch-x86/xen-x86_64.h ../xen/arch-x86/xen.h ../xen/xen.h
	python $< $* $@ $(filter %.h,$^)

ia64.h: $(ROOT)/mkheader.py ../xen/arch-ia64.h ../xen/xen.h
	python $< $* $@ $(filter %.h,$^)

checker.c: $(ROOT)/mkchecker.py
	python $< $(XEN_TARGET_ARCH) $@ $(architectures)
