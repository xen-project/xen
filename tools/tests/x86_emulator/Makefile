
XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test_x86_emulator

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$(TARGET)

SIMD := sse sse2 sse4 avx
TESTCASES := blowfish $(SIMD) sse2-avx sse4-avx

blowfish-cflags := ""
blowfish-cflags-x86_32 := "-mno-accumulate-outgoing-args -Dstatic="

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

# When converting SSE to AVX, have the compiler avoid XMM0 to widen
# coverage of the VEX.vvvv checks in the emulator. We must not do this,
# however, for SSE4.1 and later, as there are instructions with XMM0 as
# an implicit operand.
sse2avx-sse2 := -ffixed-xmm0 -Wa,-msse2avx
sse2avx-sse4 := -Wa,-msse2avx

# For AVX and later, have the compiler avoid XMM0 to widen coverage of
# the VEX.vvvv checks in the emulator.
non-sse = $(if $(filter sse%,$(1)),,-ffixed-xmm0)

define simd-defs
$(1)-cflags := \
	$(foreach vec,$($(1)-vecs), \
	  $(foreach int,$($(1)-ints), \
	    "-D_$(vec)i$(int) -m$(1) $(call non-sse,$(1)) -O2 -DVEC_SIZE=$(vec) -DINT_SIZE=$(int)" \
	    "-D_$(vec)u$(int) -m$(1) $(call non-sse,$(1)) -O2 -DVEC_SIZE=$(vec) -DUINT_SIZE=$(int)") \
	  $(foreach flt,$($(1)-flts), \
	    "-D_$(vec)f$(flt) -m$(1) $(call non-sse,$(1)) -O2 -DVEC_SIZE=$(vec) -DFLOAT_SIZE=$(flt)")) \
	$(foreach flt,$($(1)-flts), \
	  "-D_f$(flt) -m$(1) $(call non-sse,$(1)) -mfpmath=sse -O2 -DFLOAT_SIZE=$(flt)")
$(1)-avx-cflags := \
	$(foreach vec,$($(1)-vecs), \
	  $(foreach int,$($(1)-ints), \
	    "-D_$(vec)i$(int) -m$(1) $(sse2avx-$(1)) -O2 -DVEC_SIZE=$(vec) -DINT_SIZE=$(int)" \
	    "-D_$(vec)u$(int) -m$(1) $(sse2avx-$(1)) -O2 -DVEC_SIZE=$(vec) -DUINT_SIZE=$(int)"))
endef

$(foreach flavor,$(SIMD),$(eval $(call simd-defs,$(flavor))))

$(addsuffix .h,$(TESTCASES)): %.h: %.c testcase.mk Makefile
	rm -f $@.new $*.bin
	$(foreach arch,$(filter-out $(XEN_COMPILE_ARCH),x86_32) $(XEN_COMPILE_ARCH), \
	    for cflags in $($*-cflags) $($*-cflags-$(arch)); do \
		$(MAKE) -f testcase.mk TESTCASE=$* XEN_TARGET_ARCH=$(arch) $*-cflags="$$cflags" all; \
		flavor=$$(echo $${cflags} | sed -e 's, .*,,' -e 'y,-=,__,') ; \
		(echo "static const unsigned int $(subst -,_,$*)_$(arch)$${flavor}[] = {"; \
		 od -v -t x $*.bin | sed -e 's/^[0-9]* /0x/' -e 's/ /, 0x/g' -e 's/$$/,/'; \
		 echo "};") >>$@.new; \
		rm -f $*.bin; \
	    done; \
	)
	mv $@.new $@

$(addsuffix .c,$(SIMD)) $(addsuffix -avx.c,$(filter sse%,$(SIMD))):
	ln -sf simd.c $@

$(TARGET): x86-emulate.o test_x86_emulator.o
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

x86-emulate.o: x86-emulate.c x86_emulate/x86_emulate.c $(x86_emulate.h)
	$(HOSTCC) $(HOSTCFLAGS) -D__XEN_TOOLS__ -c -g -o $@ $<

test_x86_emulator.o: test_x86_emulator.c $(addsuffix .h,$(TESTCASES)) $(x86_emulate.h)
	$(HOSTCC) $(HOSTCFLAGS) -c -g -o $@ $<
