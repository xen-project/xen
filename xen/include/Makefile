ifneq ($(CONFIG_COMPAT),)

compat-arch-$(CONFIG_X86) := x86_32

headers-y := \
    compat/arch-$(compat-arch-y).h \
    compat/elfnote.h \
    compat/event_channel.h \
    compat/features.h \
    compat/memory.h \
    compat/nmi.h \
    compat/physdev.h \
    compat/platform.h \
    compat/pmu.h \
    compat/sched.h \
    compat/vcpu.h \
    compat/version.h \
    compat/xen.h \
    compat/xlat.h
headers-$(CONFIG_X86)     += compat/arch-x86/pmu.h
headers-$(CONFIG_X86)     += compat/arch-x86/xen-mca.h
headers-$(CONFIG_X86)     += compat/arch-x86/xen.h
headers-$(CONFIG_X86)     += compat/arch-x86/xen-$(compat-arch-y).h
headers-$(CONFIG_ARGO)    += compat/argo.h
headers-$(CONFIG_PV)      += compat/callback.h
headers-$(CONFIG_GRANT_TABLE) += compat/grant_table.h
headers-$(CONFIG_PV_SHIM) += compat/grant_table.h
headers-$(CONFIG_HVM)     += compat/hvm/dm_op.h
headers-$(CONFIG_HVM)     += compat/hvm/hvm_op.h
headers-$(CONFIG_HVM)     += compat/hvm/hvm_vcpu.h
headers-$(CONFIG_HYPFS)   += compat/hypfs.h
headers-$(CONFIG_KEXEC)   += compat/kexec.h
headers-$(CONFIG_TRACEBUFFER) += compat/trace.h
headers-$(CONFIG_XENOPROF) += compat/xenoprof.h
headers-$(CONFIG_XSM_FLASK) += compat/xsm/flask_op.h

cppflags-y                := -include public/xen-compat.h -DXEN_GENERATING_COMPAT_HEADERS
cppflags-$(CONFIG_X86)    += -m32

endif

public-$(CONFIG_X86) := $(wildcard $(srcdir)/public/arch-x86/*.h $(srcdir)/public/arch-x86/*/*.h)
public-$(CONFIG_ARM) := $(wildcard $(srcdir)/public/arch-arm/*.h $(srcdir)/public/arch-arm/*/*.h)

.PHONY: all
all: $(addprefix $(obj)/,$(headers-y))

$(obj)/compat/%.h: $(obj)/compat/%.i $(srcdir)/Makefile $(srctree)/tools/compat-build-header.py
	$(PYTHON) $(srctree)/tools/compat-build-header.py <$< $(patsubst $(obj)/%,%,$@) >>$@.new; \
	mv -f $@.new $@

$(obj)/compat/%.i: $(obj)/compat/%.c $(srcdir)/Makefile
	$(CPP) $(filter-out -Wa$(comma)% -include %/include/xen/config.h,$(XEN_CFLAGS)) $(cppflags-y) -o $@ $<

$(obj)/compat/%.c: $(src)/public/%.h $(srcdir)/xlat.lst $(srcdir)/Makefile $(srctree)/tools/compat-build-source.py
	mkdir -p $(@D)
	$(PYTHON) $(srctree)/tools/compat-build-source.py $(srcdir)/xlat.lst <$< >$@.new
	mv -f $@.new $@

$(obj)/compat/.xlat/%.h: $(obj)/compat/%.h $(obj)/compat/.xlat/%.lst $(srctree)/tools/get-fields.sh $(srcdir)/Makefile
	export PYTHON=$(PYTHON); \
	while read what name; do \
		$(SHELL) $(srctree)/tools/get-fields.sh "$$what" compat_$$name $< || exit $$?; \
	done <$(patsubst $(obj)/compat/%,$(obj)/compat/.xlat/%,$(basename $<)).lst >$@.new
	mv -f $@.new $@

.PRECIOUS: $(obj)/compat/.xlat/%.lst
$(obj)/compat/.xlat/%.lst: $(srcdir)/xlat.lst $(srcdir)/Makefile
	mkdir -p $(@D)
	grep -v '^[[:blank:]]*#' $< | sed -ne 's,@arch@,$(compat-arch-y),g' -re 's,[[:blank:]]+$*\.h[[:blank:]]*$$,,p' >$@.new
	$(call move-if-changed,$@.new,$@)

xlat-y := $(shell sed -ne 's,@arch@,$(compat-arch-y),g' -re 's,^[?!][[:blank:]]+[^[:blank:]]+[[:blank:]]+,,p' $(srcdir)/xlat.lst | uniq)
xlat-y := $(filter $(patsubst compat/%,%,$(headers-y)),$(xlat-y))

$(obj)/compat/xlat.h: $(addprefix $(obj)/compat/.xlat/,$(xlat-y)) $(obj)/config/auto.conf $(srcdir)/Makefile
	cat $(filter %.h,$^) >$@.new
	mv -f $@.new $@

ifeq ($(XEN_TARGET_ARCH),$(XEN_COMPILE_ARCH))

all: $(obj)/headers.chk $(obj)/headers99.chk $(obj)/headers++.chk

public-hdrs-path := $(srcdir)/public

public-list-headers = $(wildcard $1/*.h $1/*/*.h)
public-filter-headers = $(filter-out $(addprefix $(public-hdrs-path)/, $($1-filter)), $($1))

public-headers := $(call public-list-headers, $(public-hdrs-path)) $(public-y)
public-ansi-headers := $(public-headers)
public-c99-headers := $(addprefix $(public-hdrs-path)/, io/9pfs.h io/pvcalls.h)

public-headers-filter := dom0_ops.h arch-%
public-ansi-headers-filter := %ctl.h xsm/% %hvm/save.h $(public-headers-filter) \
    $(patsubst $(public-hdrs-path)/%,%,$(public-c99-headers))
public-c99-headers-filter :=

PUBLIC_HEADERS := $(call public-filter-headers,public-headers)
PUBLIC_ANSI_HEADERS := $(call public-filter-headers,public-ansi-headers)
PUBLIC_C99_HEADERS := $(call public-filter-headers,public-c99-headers)

$(src)/public/io/9pfs.h-prereq := string
$(src)/public/io/pvcalls.h-prereq := string

$(obj)/headers.chk: $(PUBLIC_ANSI_HEADERS) $(srcdir)/Makefile
	for i in $(filter %.h,$^); do \
	    $(CC) -x c -ansi -Wall -Werror -include stdint.h \
	          -S -o /dev/null $$i || exit 1; \
	    echo $$i; \
	done >$@.new
	mv $@.new $@

$(obj)/headers99.chk: $(PUBLIC_C99_HEADERS) $(srcdir)/Makefile
	rm -f $@.new
	$(foreach i, $(filter %.h,$^),                                        \
	    echo "#include "\"$(i)\"                                          \
	    | $(CC) -x c -std=c99 -Wall -Werror                               \
	      -include stdint.h $(foreach j, $($(i)-prereq), -include $(j).h) \
	      -S -o /dev/null -                                               \
	    || exit $$?; echo $(i) >> $@.new;)
	mv $@.new $@

$(obj)/headers++.chk: $(PUBLIC_HEADERS) $(srcdir)/Makefile
	rm -f $@.new
	if ! $(CXX) -v >/dev/null 2>&1; then                                  \
	    touch $@.new;                                                     \
	    exit 0;                                                           \
	fi;                                                                   \
	$(foreach i, $(filter %.h,$^),                                        \
	    echo "#include "\"$(i)\"                                          \
	    | $(CXX) -x c++ -std=gnu++98 -Wall -Werror -D__XEN_TOOLS__        \
	      -include stdint.h -include $(src)/public/xen.h                  \
	      $(foreach j, $($(i)-prereq), -include c$(j)) -S -o /dev/null -  \
	    || exit $$?; echo $(i) >> $@.new;)
	mv $@.new $@

endif

ifeq ($(XEN_TARGET_ARCH),x86_64)
.PHONY: lib-x86-all
lib-x86-all:
	$(MAKE) -C $(obj)/xen/lib/x86 all

all: lib-x86-all
endif

clean-files := compat config generated headers*.chk xen/lib/x86/cpuid-autogen.h
