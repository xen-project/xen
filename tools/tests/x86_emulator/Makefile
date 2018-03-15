
XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test_x86_emulator

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$(TARGET)

SIMD := 3dnow sse sse2 sse4 avx avx2 xop
FMA := fma4 fma
SG := avx2-sg
TESTCASES := blowfish $(SIMD) $(FMA) $(SG)

blowfish-cflags := ""
blowfish-cflags-x86_32 := "-mno-accumulate-outgoing-args -Dstatic="

3dnow-vecs := 8
3dnow-ints :=
3dnow-flts := 4
sse-vecs := 16
sse-ints :=
sse-flts := 4
sse2-vecs := $(sse-vecs)
sse2-ints := 1 2 4 8
sse2-flts := 4 8
sse4-vecs := $(sse2-vecs)
sse4-ints := $(sse2-ints)
sse4-flts := $(sse2-flts)
avx-vecs := 16 32
avx-ints :=
avx-flts := 4 8
fma4-vecs := $(avx-vecs)
fma4-ints :=
fma4-flts := $(avx-flts)
fma-vecs := $(avx-vecs)
fma-ints :=
fma-flts := $(avx-flts)
avx2-vecs := $(avx-vecs)
avx2-ints := 1 2 4 8
avx2-flts := 4 8
avx2-sg-vecs := $(avx2-vecs)
avx2-sg-idxs := 4 8
avx2-sg-ints := 4 8
avx2-sg-flts := 4 8
xop-vecs := $(avx-vecs)
xop-ints := 1 2 4 8
xop-flts := $(avx-flts)

# For AVX and later, have the compiler avoid XMM0 to widen coverage of
# the VEX.vvvv checks in the emulator.  For 3DNow!, however, force SSE
# use for floating point operations, to avoid mixing MMX and FPU register
# uses.  Also enable 3DNow! extensions, but note that we can't use 3dnowa
# as the test flavor right away since -m3dnowa is being understood only
# by gcc 7.x and newer (older ones want a specific machine model instead).
3dnowa := $(call cc-option,$(CC),-m3dnowa,-march=k8)
non-sse = $(if $(filter sse%,$(1)),,$(if $(filter 3dnow%,$(1)),-msse -mfpmath=sse $(3dnowa),-ffixed-xmm0))

define simd-defs
$(1)-cflags := \
	$(foreach vec,$($(1)-vecs), \
	  $(foreach int,$($(1)-ints), \
	    "-D_$(vec)i$(int) -m$(1) $(call non-sse,$(1)) -Os -DVEC_SIZE=$(vec) -DINT_SIZE=$(int)" \
	    "-D_$(vec)u$(int) -m$(1) $(call non-sse,$(1)) -Os -DVEC_SIZE=$(vec) -DUINT_SIZE=$(int)") \
	  $(foreach flt,$($(1)-flts), \
	    "-D_$(vec)f$(flt) -m$(1) $(call non-sse,$(1)) -Os -DVEC_SIZE=$(vec) -DFLOAT_SIZE=$(flt)")) \
	$(foreach flt,$($(1)-flts), \
	  "-D_f$(flt) -m$(1) $(call non-sse,$(1)) -mfpmath=sse -Os -DFLOAT_SIZE=$(flt)")
endef
define simd-sg-defs
$(1)-cflags := \
	$(foreach vec,$($(1)-vecs), \
	  $(foreach idx,$($(1)-idxs), \
	   $(foreach int,$($(1)-ints), \
	     "-D_$(vec)x$(idx)i$(int) -m$(1:-sg=) $(call non-sse,$(1)) -Os -DVEC_MAX=$(vec) -DIDX_SIZE=$(idx) -DINT_SIZE=$(int)") \
	   $(foreach flt,$($(1)-flts), \
	     "-D_$(vec)x$(idx)f$(flt) -m$(1:-sg=) $(call non-sse,$(1)) -Os -DVEC_MAX=$(vec) -DIDX_SIZE=$(idx) -DFLOAT_SIZE=$(flt)")))
endef

$(foreach flavor,$(SIMD) $(FMA),$(eval $(call simd-defs,$(flavor))))
$(foreach flavor,$(SG),$(eval $(call simd-sg-defs,$(flavor))))

$(addsuffix .h,$(TESTCASES)): %.h: %.c testcase.mk Makefile
	rm -f $@.new $*.bin
	$(foreach arch,$(filter-out $(XEN_COMPILE_ARCH),x86_32) $(XEN_COMPILE_ARCH), \
	    for cflags in $($*-cflags) $($*-cflags-$(arch)); do \
		$(MAKE) -f testcase.mk TESTCASE=$* XEN_TARGET_ARCH=$(arch) $*-cflags="$$cflags" all; \
		prefix=$(shell echo $(subst -,_,$*) | sed -e 's,^\([0-9]\),_\1,'); \
		flavor=$$(echo $${cflags} | sed -e 's, .*,,' -e 'y,-=,__,') ; \
		(echo 'static const unsigned int __attribute__((section(".test, \"ax\", @progbits #")))' \
		      "$${prefix}_$(arch)$${flavor}[] = {"; \
		 od -v -t x $*.bin | sed -e 's/^[0-9]* /0x/' -e 's/ /, 0x/g' -e 's/$$/,/'; \
		 echo "};") >>$@.new; \
		rm -f $*.bin; \
	    done; \
	)
	mv $@.new $@

$(addsuffix .c,$(SIMD)):
	ln -sf simd.c $@

$(addsuffix .c,$(FMA)):
	ln -sf simd-fma.c $@

$(addsuffix .c,$(SG)):
	ln -sf simd-sg.c $@

$(addsuffix .o,$(SIMD) $(FMA) $(SG)): simd.h

xop.o: simd-fma.c

$(TARGET): x86-emulate.o test_x86_emulator.o wrappers.o
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -rf $(TARGET) *.o *~ core $(addsuffix .h,$(TESTCASES)) *.bin x86_emulate asm

.PHONY: distclean
distclean: clean

.PHONY: install
install:

x86_emulate:
	[ -L $@ ] || ln -sf $(XEN_ROOT)/xen/arch/x86/$@

x86_emulate/%: x86_emulate ;

asm:
	[ -L $@ ] || ln -sf $(XEN_ROOT)/xen/include/asm-x86 $@

asm/%: asm ;

HOSTCFLAGS-x86_64 := -fno-PIE
$(call cc-option-add,HOSTCFLAGS-x86_64,HOSTCC,-no-pie)
HOSTCFLAGS += $(CFLAGS_xeninclude) -I. $(HOSTCFLAGS-$(XEN_COMPILE_ARCH))

x86.h := asm/x86-vendors.h asm/x86-defns.h asm/msr-index.h
x86_emulate.h := x86-emulate.h x86_emulate/x86_emulate.h $(x86.h)

x86-emulate.o test_x86_emulator.o wrappers.o: %.o: %.c $(x86_emulate.h)
	$(HOSTCC) $(HOSTCFLAGS) -c -g -o $@ $<

x86-emulate.o: x86_emulate/x86_emulate.c
x86-emulate.o: HOSTCFLAGS += -D__XEN_TOOLS__

test_x86_emulator.o: $(addsuffix .h,$(TESTCASES))
