ifneq ($(CONFIG_COMPAT),)

compat-arch-$(CONFIG_X86) := x86_32

headers-y                 := $(shell echo public/*.h | sed -e 's,[^[:space:]]*-[^[:space:]]*,,g' -e 's,public/,compat/,g')
headers-y                 := $(filter-out %/dom0_ops.h,$(headers-y))
headers-$(CONFIG_X86)     += compat/arch-x86/xen.h
headers-$(CONFIG_X86)     += compat/arch-x86/xen-$(compat-arch-y).h
headers-y                 += compat/arch-$(compat-arch-y).h compat/xlat.h

cppflags-y                := -include public/xen-compat.h
cppflags-$(CONFIG_X86)    += -m32

# 8-byte types are 4-byte aligned on x86_32 ...
prefix-$(CONFIG_X86)      := \#pragma pack(push, 4)
suffix-$(CONFIG_X86)      := \#pragma pack(pop)

endif

.PHONY: all
all: $(headers-y)

compat/%.h: compat/%.i Makefile
	id=_$$(echo $@ | sed 'y,abcdefghijklmnopqrstuvwxyz-/.,ABCDEFGHIJKLMNOPQRSTUVWXYZ___,'); \
	echo "#ifndef $$id" >$@.new; \
	echo "#define $$id" >>$@.new; \
	echo "#include <xen/compat.h>" >>$@.new; \
	$(if $(filter-out compat/arch-%.h,$@),echo "#include <$(patsubst compat/%,public/%,$@)>" >>$@.new;) \
	$(if $(prefix-y),echo "$(prefix-y)" >>$@.new;) \
	grep -v '^# [[:digit:]]' $< | \
	sed -e 's,__InClUdE__,#include,' \
	    -e 's,"xen-compat.h",<public/xen-compat.h>,' \
	    -e 's,\(struct\|union\|enum\)[[:space:]]\+\(xen_\?\)\?\([[:alpha:]_]\),\1 compat_\3,g' \
	    -e 's,@KeeP@,,g' \
	    -e 's,_t\([^[:alnum:]_]\|$$\),_compat_t\1,g' \
	    -e 's,\(8\|16\|32\|64\)_compat_t\([^[:alnum:]_]\|$$\),\1_t\2,g' \
	    -e 's,\(^\|[^[:alnum:]_]\)xen_\?\([[:alnum:]_]*\)_compat_t\([^[:alnum:]_]\|$$\),\1compat_\2_t\3,g' \
	    -e 's,\(^\|[^[:alnum:]_]\)XEN_\?,\1COMPAT_,' \
	    -e 's,\(^\|[^[:alnum:]_]\)Xen_\?,\1Compat_,' \
	    -e 's,\(^\|[^[:alnum:]]\)long\([^[:alnum:]]\|$$\),\1int\2,g' | \
	uniq >>$@.new; \
	$(if $(suffix-y),echo "$(suffix-y)" >>$@.new;) \
	echo "#endif /* $$id */" >>$@.new
	mv -f $@.new $@

compat/%.i: compat/%.c Makefile
	$(CPP) $(CFLAGS) $(cppflags-y) -o $@ $<

compat/%.c: public/%.h xlat.lst Makefile
	mkdir -p $(@D)
	grep -v 'DEFINE_XEN_GUEST_HANDLE(long)' $< | \
	sed -e 's,^[[:space:]]*#[[:space:]]*include[[:space:]]\+,__InClUdE__ ,' \
	    -e 's,^[[:space:]]*#[[:space:]]*define[[:space:]]\+\([[:upper:]_]*_GUEST_HANDLE\),#define HIDE_\1,' \
	    -e 's,^[[:space:]]*#[[:space:]]*define[[:space:]]\+\([[:lower:]_]*_guest_handle\),#define hide_\1,' \
	    -e 's,XEN_GUEST_HANDLE\(_[[:xdigit:]]\+\)\?,COMPAT_HANDLE,g' \
	    $(foreach n,$(shell sed -n 's,^[[:space:]]*?[[:space:]]\+\([[:alnum:]_]*\)[[:space:]].*,\1,p' xlat.lst), \
	                -e 's,\(struct\|union\)[[:space:]]\+\(xen_\?\)\?$n[[:space:]]\+\([[:alpha:]_]\),\1 @KeeP@\2$n \3,g') \
	    >$@.new
	mv -f $@.new $@

compat/xlat.h: xlat.lst $(filter-out compat/xlat.h,$(headers-y)) $(BASEDIR)/tools/get-fields.sh Makefile
	grep -v '^[[:space:]]*#' xlat.lst | \
	while read what name hdr; do \
		$(SHELL) $(BASEDIR)/tools/get-fields.sh "$$what" compat_$$name $$(echo compat/$$hdr | sed 's,@arch@,$(compat-arch-y),g') || exit $$?; \
	done >$@.new
	mv -f $@.new $@

clean::
	rm -rf compat
