
XEN_ROOT ?= $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test_x86_emulator

.PHONY: all
all:

.PHONY: run
run: $(TARGET)
	./$(TARGET)

# Add libx86 to the build
vpath %.c $(XEN_ROOT)/xen/lib/x86

CFLAGS += $(CFLAGS_xeninclude)

SIMD := 3dnow sse sse2 sse4 avx avx2 xop avx512f avx512bw avx512dq avx512er avx512vbmi
FMA := fma4 fma
SG := avx2-sg avx512f-sg avx512vl-sg
AES := ssse3-aes avx-aes avx2-vaes avx512bw-vaes
CLMUL := ssse3-pclmul avx-pclmul avx2-vpclmulqdq avx512bw-vpclmulqdq avx512vbmi2-vpclmulqdq
SHA := sse4-sha avx-sha avx512f-sha
GF := sse2-gf avx2-gf avx512bw-gf
TESTCASES := blowfish $(SIMD) $(FMA) $(SG) $(AES) $(CLMUL) $(SHA) $(GF)

OPMASK := avx512f avx512dq avx512bw

ifeq ($(origin XEN_COMPILE_ARCH),override)

HOSTCFLAGS += -m32

else

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
avx512f-vecs := 64 16 32
avx512f-ints := 4 8
avx512f-flts := 4 8
avx512f-sg-vecs := 64
avx512f-sg-idxs := 4 8
avx512f-sg-ints := $(avx512f-ints)
avx512f-sg-flts := $(avx512f-flts)
avx512vl-sg-vecs := 16 32
avx512vl-sg-idxs := $(avx512f-sg-idxs)
avx512vl-sg-ints := $(avx512f-ints)
avx512vl-sg-flts := $(avx512f-flts)
avx512bw-vecs := $(avx512f-vecs)
avx512bw-ints := 1 2
avx512bw-flts :=
avx512dq-vecs := $(avx512f-vecs)
avx512dq-ints := $(avx512f-ints)
avx512dq-flts := $(avx512f-flts)
avx512er-vecs := 64
avx512er-ints :=
avx512er-flts := 4 8
avx512vbmi-vecs := $(avx512bw-vecs)
avx512vbmi-ints := $(avx512bw-ints)
avx512vbmi-flts := $(avx512bw-flts)
avx512vbmi2-vecs := $(avx512bw-vecs)

avx512f-opmask-vecs := 2
avx512dq-opmask-vecs := 1 2
avx512bw-opmask-vecs := 4 8

# Suppress building by default of the harness if the compiler can't deal
# with some of the extensions used.  Don't alter the "run" target dependencies
# though, as this target needs to be specified manually, and things may work
# partially even with older compilers.
TARGET-y := $(TARGET)

ifeq ($(filter run%,$(MAKECMDGOALS)),)

define simd-check-cc
TARGET-$(shell echo 'int i;' | $(CC) -x c -c -o /dev/null -m$(1) - || echo y) :=
endef

$(foreach flavor,$(SIMD) $(FMA),$(eval $(call simd-check-cc,$(flavor))))

# Also explicitly check for {evex} pseudo-prefix support, which got introduced
# only after AVX512F and some of its extensions.
TARGET-$(shell echo 'asm("{evex} vmovaps %xmm0$(comma)%xmm0");' | $(CC) -x c -c -o /dev/null - || echo y) :=

ifeq ($(TARGET-y),)
$(warning Test harness not built, use newer compiler than "$(CC)" (version $(shell $(CC) -dumpversion)) and an "{evex}" capable assembler)
endif

endif

all: $(TARGET-y)

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
define simd-aes-defs
$(1)-cflags := $(foreach vec,$($(patsubst %-aes,sse,$(1))-vecs) $($(patsubst %-vaes,%,$(1))-vecs), \
	         "-D_$(vec) -maes $(addprefix -m,$(subst -,$(space),$(1))) $(call non-sse,$(1)) -Os -DVEC_SIZE=$(vec)")
endef
define simd-clmul-defs
$(1)-cflags := $(foreach vec,$($(patsubst %-pclmul,sse,$(1))-vecs) $($(patsubst %-vpclmulqdq,%,$(1))-vecs), \
	         "-D_$(vec) -mpclmul $(addprefix -m,$(subst -,$(space),$(1))) $(call non-sse,$(1)) -Os -DVEC_SIZE=$(vec)")
endef
define simd-sha-defs
$(1)-cflags := $(foreach vec,$(sse-vecs), \
	         "-D_$(vec) $(addprefix -m,$(subst -,$(space),$(1))) -Os -DVEC_SIZE=$(vec)")
endef
define simd-gf-defs
$(1)-cflags := $(foreach vec,$($(1:-gf=)-vecs), \
	         "-D_$(vec) -mgfni -m$(1:-gf=) $(call non-sse,$(1)) -Os -DVEC_SIZE=$(vec)")
endef
define opmask-defs
$(1)-opmask-cflags := $(foreach vec,$($(1)-opmask-vecs), "-D_$(vec) -m$(1) -Os -DSIZE=$(vec)")
endef

$(foreach flavor,$(SIMD) $(FMA),$(eval $(call simd-defs,$(flavor))))
$(foreach flavor,$(SG),$(eval $(call simd-sg-defs,$(flavor))))
$(foreach flavor,$(AES),$(eval $(call simd-aes-defs,$(flavor))))
$(foreach flavor,$(CLMUL),$(eval $(call simd-clmul-defs,$(flavor))))
$(foreach flavor,$(SHA),$(eval $(call simd-sha-defs,$(flavor))))
$(foreach flavor,$(GF),$(eval $(call simd-gf-defs,$(flavor))))
$(foreach flavor,$(OPMASK),$(eval $(call opmask-defs,$(flavor))))

first-string = $(shell for s in $(1); do echo "$$s"; break; done)

avx2-sg-cflags-x86_64    := "-D_high $(foreach n,7 6 5 4 3 2 1,-ffixed-ymm$(n)) $(call first-string,$(avx2-sg-cflags))"
avx512f-sg-cflags-x86_64 := "-D_higher $(foreach n,7 6 5 4 3 2 1,-ffixed-zmm$(n)) $(call first-string,$(avx512f-sg-cflags))"
avx512f-sg-cflags-x86_64 += "-D_highest $(foreach n,15 14 13 12 11 10 9 8,-ffixed-zmm$(n)) $(call first-string,$(avx512f-sg-cflags-x86_64))"

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
		 echo "};"; \
		 echo "asm(\".type $${prefix}_$(arch)$${flavor}, STT_NOTYPE;\");"; \
		 echo "asm(\".type $${prefix}_$(arch)$${flavor}, STT_FUNC;\");"; \
		) >>$@.new; \
		rm -f $*.bin; \
	    done; \
	)
	mv $@.new $@

$(addsuffix -opmask.h,$(OPMASK)): %.h: opmask.S testcase.mk Makefile
	rm -f $@.new $*.bin
	$(foreach arch,$(filter-out $(XEN_COMPILE_ARCH),x86_32) $(XEN_COMPILE_ARCH), \
	    for cflags in $($*-cflags) $($*-cflags-$(arch)); do \
		$(MAKE) -f testcase.mk TESTCASE=$* XEN_TARGET_ARCH=$(arch) $*-cflags="$$cflags" all; \
		prefix=$(shell echo $(subst -,_,$*) | sed -e 's,^\([0-9]\),_\1,'); \
		flavor=$$(echo $${cflags} | sed -e 's, .*,,' -e 'y,-=,__,') ; \
		(echo 'static const unsigned int __attribute__((section(".test, \"ax\", @progbits #")))' \
		      "$${prefix}_$(arch)$${flavor}[] = {"; \
		 od -v -t x $*.bin | sed -e 's/^[0-9]* /0x/' -e 's/ /, 0x/g' -e 's/$$/,/'; \
		 echo "};"; \
		 echo "asm(\".type $${prefix}_$(arch)$${flavor}, STT_NOTYPE;\");"; \
		 echo "asm(\".type $${prefix}_$(arch)$${flavor}, STT_FUNC;\");"; \
		) >>$@.new; \
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

$(addsuffix .c,$(AES)):
	ln -sf simd-aes.c $@

$(addsuffix .c,$(CLMUL)):
	ln -sf simd-clmul.c $@

$(addsuffix .c,$(SHA)):
	ln -sf simd-sha.c $@

$(addsuffix .c,$(GF)):
	ln -sf simd-gf.c $@

$(addsuffix .h,$(SIMD) $(FMA) $(SG) $(AES) $(CLMUL) $(SHA) $(GF)): simd.h

xop.h avx512f.h: simd-fma.c

endif # 32-bit override

$(TARGET): x86-emulate.o cpuid.o test_x86_emulator.o evex-disp8.o predicates.o wrappers.o
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -rf $(TARGET) *.o *~ core *.bin x86_emulate
	rm -rf $(TARGET) $(addsuffix .h,$(TESTCASES)) $(addsuffix -opmask.h,$(OPMASK))

.PHONY: distclean
distclean: clean

.PHONY: install uninstall
install uninstall:

.PHONY: run32 clean32
ifeq ($(XEN_COMPILE_ARCH),x86_64)
run32: $(addsuffix .h,$(TESTCASES)) $(addsuffix -opmask.h,$(OPMASK))
run32 clean32: %32:
	$(MAKE) -C 32 HOSTCC=$(HOSTCC) $*
clean: clean32
else
run32 clean32: %32: %
endif

x86_emulate:
	[ -L $@ ] || ln -sf $(XEN_ROOT)/xen/arch/x86/$@

x86_emulate/%: x86_emulate ;

HOSTCFLAGS-x86_64 := -fno-PIE
$(call cc-option-add,HOSTCFLAGS-x86_64,HOSTCC,-no-pie)
HOSTCFLAGS += $(CFLAGS_xeninclude) -I. $(HOSTCFLAGS-$(XEN_COMPILE_ARCH))

x86.h := $(addprefix $(XEN_ROOT)/tools/include/xen/asm/,\
                     x86-vendors.h x86-defns.h msr-index.h) \
         $(addprefix $(XEN_ROOT)/tools/include/xen/lib/x86/, \
                     cpuid.h cpuid-autogen.h)
x86_emulate.h := x86-emulate.h x86_emulate/x86_emulate.h $(x86.h)

x86-emulate.o cpuid.o test_x86_emulator.o evex-disp8.o predicates.o wrappers.o: %.o: %.c $(x86_emulate.h)
	$(HOSTCC) $(HOSTCFLAGS) -c -g -o $@ $<

x86-emulate.o: x86_emulate/x86_emulate.c
x86-emulate.o: HOSTCFLAGS += -D__XEN_TOOLS__

test_x86_emulator.o: $(addsuffix .h,$(TESTCASES)) $(addsuffix -opmask.h,$(OPMASK))
