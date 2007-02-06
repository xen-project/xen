ifneq ($(CONFIG_COMPAT),)

compat-arch-$(CONFIG_X86) := x86_32

headers-y := \
    compat/acm.h \
    compat/acm_ops.h \
    compat/callback.h \
    compat/elfnote.h \
    compat/event_channel.h \
    compat/features.h \
    compat/grant_table.h \
    compat/kexec.h \
    compat/memory.h \
    compat/nmi.h \
    compat/physdev.h \
    compat/platform.h \
    compat/sched.h \
    compat/trace.h \
    compat/vcpu.h \
    compat/version.h \
    compat/xen.h \
    compat/xencomm.h \
    compat/xenoprof.h
headers-$(CONFIG_X86)     += compat/arch-x86/xen.h
headers-$(CONFIG_X86)     += compat/arch-x86/xen-$(compat-arch-y).h
headers-y                 += compat/arch-$(compat-arch-y).h compat/xlat.h

cppflags-y                := -include public/xen-compat.h
cppflags-$(CONFIG_X86)    += -m32

# 8-byte types are 4-byte aligned on x86_32 ...
prefix-$(CONFIG_X86)      := \#pragma pack(4)
suffix-$(CONFIG_X86)      := \#pragma pack()

endif

.PHONY: all
all: $(headers-y)

compat/%.h: compat/%.i Makefile
	id=_$$(echo $@ | tr '[:lower:]-/.' '[:upper:]___'); \
	echo "#ifndef $$id" >$@.new; \
	echo "#define $$id" >>$@.new; \
	echo "#include <xen/compat.h>" >>$@.new; \
	$(if $(filter-out compat/arch-%.h,$@),echo "#include <$(patsubst compat/%,public/%,$@)>" >>$@.new;) \
	$(if $(prefix-y),echo "$(prefix-y)" >>$@.new;) \
	grep -v '^# [0-9]' $< | \
	$(BASEDIR)/tools/compat-build-header.py | uniq >>$@.new; \
	$(if $(suffix-y),echo "$(suffix-y)" >>$@.new;) \
	echo "#endif /* $$id */" >>$@.new
	mv -f $@.new $@

compat/%.i: compat/%.c Makefile
	$(CPP) $(CFLAGS) $(cppflags-y) -o $@ $<

compat/%.c: public/%.h xlat.lst Makefile
	mkdir -p $(@D)
	grep -v 'DEFINE_XEN_GUEST_HANDLE(long)' $< | \
        $(BASEDIR)/tools/compat-build-source.py >$@.new
	mv -f $@.new $@

compat/xlat.h: xlat.lst $(filter-out compat/xlat.h,$(headers-y)) $(BASEDIR)/tools/get-fields.sh Makefile
	grep -v '^[	 ]*#' xlat.lst | \
	while read what name hdr; do \
		/bin/bash $(BASEDIR)/tools/get-fields.sh "$$what" compat_$$name $$(echo compat/$$hdr | sed 's,@arch@,$(compat-arch-y),g') || exit $$?; \
	done >$@.new
	mv -f $@.new $@

clean::
	rm -rf compat
