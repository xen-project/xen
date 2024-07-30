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

headers-n := $(sort $(filter-out $(headers-y),$(headers-n) $(headers-)))

cppflags-y                := -include public/xen-compat.h -DXEN_GENERATING_COMPAT_HEADERS
cppflags-$(CONFIG_X86)    += -m32

endif

public-$(CONFIG_X86) := $(wildcard $(srcdir)/public/arch-x86/*.h $(srcdir)/public/arch-x86/*/*.h)
public-$(CONFIG_ARM) := $(wildcard $(srcdir)/public/arch-arm/*.h $(srcdir)/public/arch-arm/*/*.h)

.PHONY: all
all: $(addprefix $(obj)/,$(headers-y) $(headers-n))

quiet_cmd_compat_h = GEN     $@
cmd_compat_h = \
    $(PYTHON) $(srctree)/tools/compat-build-header.py <$< $(patsubst $(obj)/%,%,$@) >>$@.new; \
    mv -f $@.new $@

quiet_cmd_stub_h = GEN     $@
cmd_stub_h = echo '/* SAF-9-safe empty header */' >$@

quiet_cmd_compat_i = CPP     $@
cmd_compat_i = $(CPP) $(filter-out -Wa$(comma)% -include %/include/xen/config.h,$(XEN_CFLAGS)) $(cppflags-y) -o $@ $<

quiet_cmd_compat_c = GEN     $@
cmd_compat_c = \
   $(PYTHON) $(srctree)/tools/compat-build-source.py $(srcdir)/xlat.lst <$< >$@.new; \
   mv -f $@.new $@

quiet_cmd_xlat_headers = GEN     $@
cmd_xlat_headers = \
    $(PYTHON) $(srctree)/tools/compat-xlat-header.py $< $(patsubst $(obj)/compat/%,$(obj)/compat/.xlat/%,$(basename $<)).lst > $@.new; \
    mv -f $@.new $@

targets += $(headers-y)
$(obj)/compat/%.h: $(obj)/compat/%.i $(srctree)/tools/compat-build-header.py FORCE
	$(call if_changed,compat_h)

# Placeholders may be needed in case files in $(headers-y) include files we
# don't otherwise generate.  Real dependencies would need spelling out explicitly,
# for them to appear in $(headers-y) instead.
targets += $(headers-n)
$(addprefix $(obj)/,$(headers-n)): FORCE
	$(call if_changed,stub_h)

.PRECIOUS: $(obj)/compat/%.i
targets += $(patsubst %.h, %.i, $(headers-y))
$(obj)/compat/%.i: $(obj)/compat/%.c FORCE
	$(call if_changed,compat_i)

.PRECIOUS: $(obj)/compat/%.c
targets += $(patsubst %.h, %.c, $(headers-y))
$(obj)/compat/%.c: $(src)/public/%.h $(srcdir)/xlat.lst $(srctree)/tools/compat-build-source.py FORCE
	$(call if_changed,compat_c)

targets += $(patsubst compat/%, compat/.xlat/%, $(headers-y))
$(obj)/compat/.xlat/%.h: $(obj)/compat/%.h $(obj)/compat/.xlat/%.lst $(srctree)/tools/compat-xlat-header.py FORCE
	$(call if_changed,xlat_headers)

filechk_xlat_lst = \
	sed -ne '/^[[:blank:]]*$(pound)/d' -e 's,@arch@,$(compat-arch-y),g' -re 's,[[:blank:]]+$*\.h[[:blank:]]*$$,,p' $<

.PRECIOUS: $(obj)/compat/.xlat/%.lst
targets += $(patsubst compat/%.h, compat/.xlat/%.lst, $(headers-y))
$(obj)/compat/.xlat/%.lst: $(srcdir)/xlat.lst FORCE
	$(call filechk,xlat_lst)

xlat-y := $(shell sed -ne 's,@arch@,$(compat-arch-y),g' -re 's,^[?!][[:blank:]]+[^[:blank:]]+[[:blank:]]+,,p' $(srcdir)/xlat.lst | uniq)
xlat-y := $(filter $(patsubst compat/%,%,$(headers-y)),$(xlat-y))

quiet_cmd_xlat_h = GEN     $@
cmd_xlat_h = \
	cat $(filter %.h,$^) >$@.new; \
	mv -f $@.new $@

$(obj)/compat/xlat.h: $(addprefix $(obj)/compat/.xlat/,$(xlat-y)) FORCE
	$(call if_changed,xlat_h)

quiet_cmd_genhyp = GEN     $@
define cmd_genhyp
    awk -f $(srctree)/scripts/gen_hypercall.awk <$< >$@
endef

all: $(obj)/xen/hypercall-defs.h

$(obj)/xen/hypercall-defs.h: $(obj)/hypercall-defs.i $(srctree)/scripts/gen_hypercall.awk FORCE
	$(call if_changed,genhyp)

targets += hypercall-defs.i xen/hypercall-defs.h

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

quiet_cmd_header_chk = CHK     $@
cmd_header_chk = \
	for i in $(filter %.h,$^); do \
	    $(CC) -x c -ansi -Wall -Werror -include stdint.h \
	          -S -o /dev/null $$i || exit 1; \
	    echo $$i; \
	done >$@.new; \
	mv $@.new $@

quiet_cmd_headers99_chk = CHK     $@
define cmd_headers99_chk
	rm -f $@.new; \
	get_prereq() {                                                        \
	    case $$1 in                                                       \
	    $(foreach i, $(filter %.h,$^),                                    \
	    $(if $($(patsubst $(srctree)/%,%,$(i))-prereq),                   \
	        $(i)$(close)                                                  \
	        echo "$(foreach j, $($(patsubst $(srctree)/%,%,$(i))-prereq), \
	                -include $(j).h)";;))                                 \
	    *) ;;                                                             \
	    esac;                                                             \
	};                                                                    \
	for i in $(filter %.h,$^); do                                         \
	    echo "#include "\"$$i\"                                           \
	    | $(CC) -x c -std=c99 -Wall -Werror                               \
	      -include stdint.h                                               \
	      $$(get_prereq $$i)                                              \
	      -S -o /dev/null -                                               \
	    || exit $$?; echo $$i >> $@.new;                                  \
	done;                                                                 \
	mv $@.new $@
endef

quiet_cmd_headerscxx_chk = CHK     $@
define cmd_headerscxx_chk
	rm -f $@.new; \
	if ! $(CXX) -v >/dev/null 2>&1; then                                  \
	    touch $@.new;                                                     \
	    exit 0;                                                           \
	fi;                                                                   \
	get_prereq() {                                                        \
	    case $$1 in                                                       \
	    $(foreach i, $(filter %.h,$^),                                    \
	    $(if $($(patsubst $(srctree)/%,%,$(i))-prereq),                   \
	        $(i)$(close)                                                  \
	        echo "$(foreach j, $($(patsubst $(srctree)/%,%,$(i))-prereq), \
	                -include c$(j))";;))                                  \
	    *) ;;                                                             \
	    esac;                                                             \
	};                                                                    \
	for i in $(filter %.h,$^); do                                         \
	    echo "#include "\"$$i\"                                           \
	    | $(CXX) -x c++ -std=gnu++98 -Wall -Werror -D__XEN_TOOLS__        \
	      -include stdint.h -include $(srcdir)/public/xen.h               \
	      $$(get_prereq $$i)                                              \
	      -S -o /dev/null -                                               \
	    || exit $$?; echo $$i >> $@.new; done;                            \
	mv $@.new $@
endef

targets += headers.chk
$(obj)/headers.chk: $(PUBLIC_ANSI_HEADERS) FORCE
	$(call if_changed,header_chk)

targets += headers99.chk
$(obj)/headers99.chk: $(PUBLIC_C99_HEADERS) FORCE
	$(call if_changed,headers99_chk)

targets += headers++.chk
$(obj)/headers++.chk: $(PUBLIC_HEADERS) FORCE
	$(call if_changed,headerscxx_chk)

endif

ifeq ($(XEN_TARGET_ARCH),x86_64)
.PHONY: lib-x86-all
lib-x86-all:
	@mkdir -p $(obj)/xen/lib/x86
	$(Q)$(MAKE) -C $(obj)/xen/lib/x86 -f $(abs_srctree)/$(src)/xen/lib/x86/Makefile all

all: lib-x86-all
endif

clean-files := compat config generated xen/lib/x86/cpuid-autogen.h
