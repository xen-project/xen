include $(XEN_ROOT)/Config.mk

ifneq ($(CONFIG_COMPAT),)

compat-arch-$(CONFIG_X86) := x86_32

headers-y := \
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
    compat/tmem.h \
    compat/trace.h \
    compat/vcpu.h \
    compat/version.h \
    compat/xen.h \
    compat/xencomm.h \
    compat/xenoprof.h
headers-$(CONFIG_X86)     += compat/arch-x86/xen-mca.h
headers-$(CONFIG_X86)     += compat/arch-x86/xen.h
headers-$(CONFIG_X86)     += compat/arch-x86/xen-$(compat-arch-y).h
headers-y                 += compat/arch-$(compat-arch-y).h compat/xlat.h
headers-$(FLASK_ENABLE)   += compat/xsm/flask_op.h

cppflags-y                := -include public/xen-compat.h
cppflags-$(CONFIG_X86)    += -m32

# 8-byte types are 4-byte aligned on x86_32 ...
prefix-$(CONFIG_X86)      := \#pragma pack(4)
suffix-$(CONFIG_X86)      := \#pragma pack()

endif

public-$(CONFIG_X86) := $(wildcard public/arch-x86/*.h public/arch-x86/*/*.h)
public-$(CONFIG_ARM) := $(wildcard public/arch-arm/*.h public/arch-arm/*/*.h)

.PHONY: all
all: $(headers-y)

compat/%.h: compat/%.i Makefile $(BASEDIR)/tools/compat-build-header.py
	set -e; id=_$$(echo $@ | tr '[:lower:]-/.' '[:upper:]___'); \
	echo "#ifndef $$id" >$@.new; \
	echo "#define $$id" >>$@.new; \
	echo "#include <xen/compat.h>" >>$@.new; \
	$(if $(filter-out compat/arch-%.h,$@),echo "#include <$(patsubst compat/%,public/%,$@)>" >>$@.new;) \
	$(if $(prefix-y),echo "$(prefix-y)" >>$@.new;) \
	grep -v '^# [0-9]' $< | \
	$(PYTHON) $(BASEDIR)/tools/compat-build-header.py | uniq >>$@.new; \
	$(if $(suffix-y),echo "$(suffix-y)" >>$@.new;) \
	echo "#endif /* $$id */" >>$@.new
	mv -f $@.new $@

compat/%.i: compat/%.c Makefile
	$(CPP) $(filter-out -M% .%.d -include %/include/xen/config.h,$(CFLAGS)) $(cppflags-y) -o $@ $<

compat/%.c: public/%.h xlat.lst Makefile $(BASEDIR)/tools/compat-build-source.py
	mkdir -p $(@D)
	grep -v 'DEFINE_XEN_GUEST_HANDLE(long)' $< | \
	$(PYTHON) $(BASEDIR)/tools/compat-build-source.py >$@.new
	mv -f $@.new $@

compat/.xlat/%.h: compat/%.h compat/.xlat/%.lst $(BASEDIR)/tools/get-fields.sh Makefile
	export PYTHON=$(PYTHON); \
	while read what name; do \
		$(SHELL) $(BASEDIR)/tools/get-fields.sh "$$what" compat_$$name $< || exit $$?; \
	done <$(patsubst compat/%,compat/.xlat/%,$(basename $<)).lst >$@.new
	mv -f $@.new $@

.PRECIOUS: compat/.xlat/%.lst
compat/.xlat/%.lst: xlat.lst Makefile
	mkdir -p $(@D)
	grep -v '^[[:blank:]]*#' $< | sed -ne 's,@arch@,$(compat-arch-y),g' -re 's,[[:blank:]]+$*\.h[[:blank:]]*$$,,p' >$@.new
	$(call move-if-changed,$@.new,$@)

xlat-y := $(shell sed -ne 's,@arch@,$(compat-arch-y),g' -re 's,^[?!][[:blank:]]+[^[:blank:]]+[[:blank:]]+,,p' xlat.lst | uniq)
xlat-y := $(filter $(patsubst compat/%,%,$(headers-y)),$(xlat-y))

compat/xlat.h: $(addprefix compat/.xlat/,$(xlat-y)) Makefile
	cat $(filter %.h,$^) >$@.new
	mv -f $@.new $@

ifeq ($(XEN_TARGET_ARCH),$(XEN_COMPILE_ARCH))

all: headers.chk

headers.chk: $(filter-out public/arch-% public/%ctl.h public/xsm/% public/%hvm/save.h, $(wildcard public/*.h public/*/*.h) $(public-y)) Makefile
	for i in $(filter %.h,$^); do $(CC) -ansi -include stdint.h -Wall -W -Werror -S -o /dev/null -x c $$i || exit 1; echo $$i; done >$@.new
	mv $@.new $@

endif

clean::
	rm -rf compat headers.chk
