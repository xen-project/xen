obj-y += acpi/
obj-y += boot/
obj-y += cpu/
obj-y += efi/
obj-y += genapic/
obj-$(CONFIG_GUEST) += guest/
obj-$(CONFIG_HVM) += hvm/
obj-y += mm/
obj-$(CONFIG_XENOPROF) += oprofile/
obj-$(CONFIG_PV) += pv/
obj-y += x86_64/
obj-y += x86_emulate/

alternative-y := alternative.init.o
alternative-$(CONFIG_LIVEPATCH) :=
obj-bin-y += $(alternative-y)
obj-y += apic.o
obj-y += bhb-thunk.o
obj-y += bitops.o
obj-bin-y += bzimage.init.o
obj-bin-y += clear_page.o
obj-bin-y += copy_page.o
obj-y += cpu-policy.o
obj-y += cpuid.o
obj-$(CONFIG_PV) += compat.o
obj-$(CONFIG_PV32) += x86_64/compat.o
obj-$(CONFIG_KEXEC) += crash.o
obj-y += debug.o
obj-y += delay.o
obj-y += desc.o
obj-bin-y += dmi_scan.init.o
obj-y += domain.o
obj-bin-y += dom0_build.init.o
obj-y += domain_page.o
obj-y += e820.o
obj-y += emul-i8254.o
obj-y += extable.o
obj-y += flushtlb.o
obj-$(CONFIG_GDBSX) += gdbsx.o
obj-y += hypercall.o
obj-y += i387.o
obj-y += i8259.o
obj-y += io_apic.o
obj-$(CONFIG_LIVEPATCH) += alternative.o livepatch.o
obj-y += msi.o
obj-y += msr.o
obj-$(CONFIG_INDIRECT_THUNK) += indirect-thunk.o
obj-$(CONFIG_PV) += ioport_emulate.o
obj-y += irq.o
obj-$(CONFIG_KEXEC) += machine_kexec.o
obj-y += mm.o x86_64/mm.o
obj-$(CONFIG_HVM) += monitor.o
obj-y += mpparse.o
obj-y += nmi.o
obj-y += numa.o
obj-y += pci.o
obj-y += physdev.o
obj-$(CONFIG_COMPAT) += x86_64/physdev.o
obj-$(CONFIG_X86_PSR) += psr.o
obj-y += setup.o
obj-y += shutdown.o
obj-y += smp.o
obj-y += smpboot.o
obj-y += spec_ctrl.o
obj-y += srat.o
obj-y += string.o
obj-y += time.o
obj-y += traps.o
obj-$(CONFIG_INTEL) += tsx.o
obj-y += usercopy.o
obj-y += x86_emulate.o
obj-$(CONFIG_TBOOT) += tboot.o
obj-y += hpet.o
obj-y += vm_event.o
obj-y += xstate.o

ifneq ($(CONFIG_PV_SHIM_EXCLUSIVE),y)
obj-y += domctl.o
obj-y += platform_hypercall.o
obj-$(CONFIG_COMPAT) += x86_64/platform_hypercall.o
obj-y += sysctl.o
endif

extra-y += asm-macros.i
extra-y += xen.lds

hostprogs-y += boot/mkelf32
hostprogs-y += efi/mkreloc

$(obj)/efi/mkreloc: HOSTCFLAGS += -I$(srctree)/include

# Allows usercopy.c to include itself
$(obj)/usercopy.o: CFLAGS-y += -iquote .

ifneq ($(CONFIG_HVM),y)
$(obj)/x86_emulate.o: CFLAGS-y += -Wno-unused-label
endif

efi-y := $(shell if [ ! -r $(objtree)/include/xen/compile.h -o \
                      -O $(objtree)/include/xen/compile.h ]; then \
                         echo '$(TARGET).efi'; fi) \
         $(space)
efi-$(CONFIG_PV_SHIM_EXCLUSIVE) :=

ifneq ($(build_id_linker),)
notes_phdrs = --notes
else
ifeq ($(CONFIG_PVH_GUEST),y)
notes_phdrs = --notes
endif
endif

ifdef CONFIG_LIVEPATCH
all_symbols = --all-symbols
ifdef CONFIG_FAST_SYMBOL_LOOKUP
all_symbols = --all-symbols --sort-by-name
endif
else
all_symbols =
endif

syms-warn-dup-y := --warn-dup
syms-warn-dup-$(CONFIG_SUPPRESS_DUPLICATE_SYMBOL_WARNINGS) :=
syms-warn-dup-$(CONFIG_ENFORCE_UNIQUE_SYMBOLS) := --error-dup

orphan-handling-$(call ld-option,--orphan-handling=warn) += --orphan-handling=warn

$(TARGET): TMP = $(dot-target).elf32
$(TARGET): $(TARGET)-syms $(efi-y) $(obj)/boot/mkelf32
	$(obj)/boot/mkelf32 $(notes_phdrs) $(TARGET)-syms $(TMP) $(XEN_IMG_OFFSET) \
	               `$(NM) $(TARGET)-syms | sed -ne 's/^\([^ ]*\) . __2M_rwdata_end$$/0x\1/p'`
	od -t x4 -N 8192 $(TMP)  | grep 1badb002 > /dev/null || \
		{ echo "No Multiboot1 header found" >&2; false; }
	od -t x4 -N 32768 $(TMP) | grep e85250d6 > /dev/null || \
		{ echo "No Multiboot2 header found" >&2; false; }
	mv $(TMP) $(TARGET)

CFLAGS-$(XEN_BUILD_EFI) += -DXEN_BUILD_EFI

$(TARGET)-syms: $(objtree)/prelink.o $(obj)/xen.lds
	$(LD) $(XEN_LDFLAGS) -T $(obj)/xen.lds -N $< $(build_id_linker) \
	    $(objtree)/common/symbols-dummy.o -o $(dot-target).0
	$(NM) -pa --format=sysv $(dot-target).0 \
		| $(objtree)/tools/symbols $(all_symbols) --sysv --sort \
		> $(dot-target).0.S
	$(MAKE) $(build)=$(@D) $(dot-target).0.o
	$(LD) $(XEN_LDFLAGS) -T $(obj)/xen.lds -N $< $(build_id_linker) \
	    $(dot-target).0.o -o $(dot-target).1
	$(NM) -pa --format=sysv $(dot-target).1 \
		| $(objtree)/tools/symbols $(all_symbols) --sysv --sort $(syms-warn-dup-y) \
		> $(dot-target).1.S
	$(MAKE) $(build)=$(@D) $(dot-target).1.o
	$(LD) $(XEN_LDFLAGS) -T $(obj)/xen.lds -N $< $(build_id_linker) \
	    $(orphan-handling-y) $(dot-target).1.o -o $@
	$(NM) -pa --format=sysv $@ \
		| $(objtree)/tools/symbols --all-symbols --xensyms --sysv --sort \
		> $@.map
	rm -f $(dot-target).[0-9]* $(@D)/..$(@F).[0-9]*
ifeq ($(CONFIG_XEN_IBT),y)
	$(SHELL) $(srctree)/tools/check-endbr.sh $@
endif

$(obj)/note.o: $(TARGET)-syms
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $< $@.bin
	$(OBJCOPY) -I binary -O elf64-x86-64 -B i386:x86-64 \
		--rename-section=.data=.note.gnu.build-id -S $@.bin $@
	rm -f $@.bin

EFI_LDFLAGS += --image-base=$(1) --stack=0,0 --heap=0,0
EFI_LDFLAGS += --section-alignment=0x200000 --file-alignment=0x20
EFI_LDFLAGS += --major-image-version=$(XEN_VERSION)
EFI_LDFLAGS += --minor-image-version=$(XEN_SUBVERSION)
EFI_LDFLAGS += --major-os-version=2 --minor-os-version=0
EFI_LDFLAGS += --major-subsystem-version=2 --minor-subsystem-version=0
# It seems ld unfortunately can't set a custom timestamp, so add a zero value
# for the timestamp (option --no-insert-timestamp) if SOURCE_DATE_EPOCH is
# defined to make reproducible builds possible.
ifdef SOURCE_DATE_EPOCH
EFI_LDFLAGS += --no-insert-timestamp
endif

$(TARGET).efi: VIRT_BASE = 0x$(shell $(NM) $(obj)/efi/relocs-dummy.o | sed -n 's, A VIRT_START$$,,p')
ifeq ($(MKRELOC),:)
relocs-dummy :=
$(TARGET).efi: ALT_BASE :=
else
relocs-dummy := $(obj)/efi/relocs-dummy.o
$(TARGET).efi: ALT_BASE = 0x$(shell $(NM) $(obj)/efi/relocs-dummy.o | sed -n 's, A ALT_START$$,,p')
endif

ifneq ($(build_id_linker),)
ifeq ($(call ld-ver-build-id,$(LD) $(filter -m%,$(EFI_LDFLAGS))),y)
CFLAGS-y += -DBUILD_ID_EFI
EFI_LDFLAGS += $(build_id_linker)
note_file := $(obj)/efi/buildid.o
# NB: this must be the last input in the linker call, because inputs following
# the -b option will all be treated as being in the specified format.
note_file_option := -b pe-x86-64 $(note_file)
else
note_file := $(obj)/note.o
endif
else
note_file :=
endif
note_file_option ?= $(note_file)

extra-$(XEN_BUILD_PE) += efi.lds
ifeq ($(XEN_BUILD_PE),y)
$(TARGET).efi: $(objtree)/prelink.o $(note_file) $(obj)/efi.lds $(obj)/efi/relocs-dummy.o $(obj)/efi/mkreloc
ifeq ($(CONFIG_DEBUG_INFO),y)
	$(if $(filter --strip-debug,$(EFI_LDFLAGS)),echo,:) "Will strip debug info from $(@F)"
endif
	$(foreach base, $(VIRT_BASE) $(ALT_BASE), \
	          $(LD) $(call EFI_LDFLAGS,$(base)) -T $(obj)/efi.lds -N $< $(relocs-dummy) \
	                $(objtree)/common/symbols-dummy.o $(note_file_option) \
	                -o $(dot-target).$(base).0 &&) :
	$(MKRELOC) $(foreach base,$(VIRT_BASE) $(ALT_BASE),$(dot-target).$(base).0) \
		> $(dot-target).0r.S
	$(NM) -pa --format=sysv $(dot-target).$(VIRT_BASE).0 \
		| $(objtree)/tools/symbols $(all_symbols) --sysv --sort \
		> $(dot-target).0s.S
	$(MAKE) $(build)=$(@D) .$(@F).0r.o .$(@F).0s.o
	$(foreach base, $(VIRT_BASE) $(ALT_BASE), \
	          $(LD) $(call EFI_LDFLAGS,$(base)) -T $(obj)/efi.lds -N $< \
	                $(dot-target).0r.o $(dot-target).0s.o $(note_file_option) \
	                -o $(dot-target).$(base).1 &&) :
	$(MKRELOC) $(foreach base,$(VIRT_BASE) $(ALT_BASE),$(dot-target).$(base).1) \
		> $(dot-target).1r.S
	$(NM) -pa --format=sysv $(dot-target).$(VIRT_BASE).1 \
		| $(objtree)/tools/symbols $(all_symbols) --sysv --sort \
		> $(dot-target).1s.S
	$(MAKE) $(build)=$(@D) .$(@F).1r.o .$(@F).1s.o
	$(LD) $(call EFI_LDFLAGS,$(VIRT_BASE)) -T $(obj)/efi.lds -N $< \
	      $(dot-target).1r.o $(dot-target).1s.o $(orphan-handling-y) \
	      $(note_file_option) -o $@
	$(NM) -pa --format=sysv $@ \
		| $(objtree)/tools/symbols --all-symbols --xensyms --sysv --sort \
		> $@.map
ifeq ($(CONFIG_DEBUG_INFO),y)
	$(if $(filter --strip-debug,$(EFI_LDFLAGS)),:$(space))$(OBJCOPY) -O elf64-x86-64 $@ $@.elf
endif
	rm -f $(dot-target).[0-9]* $(@D)/..$(@F).[0-9]*
ifeq ($(CONFIG_XEN_IBT),y)
	$(SHELL) $(srctree)/tools/check-endbr.sh $@
endif
else
$(TARGET).efi: FORCE
	rm -f $@
	echo '$(if $(filter y,$(XEN_BUILD_EFI)),xen.efi generation,EFI support) disabled'
endif

# These should already have been rebuilt when building the prerequisite of "prelink.o"
$(obj)/efi/buildid.o $(obj)/efi/relocs-dummy.o: ;

.PHONY: include
include: $(objtree)/arch/x86/include/asm/asm-macros.h

$(obj)/asm-macros.i: CFLAGS-y += -P

$(objtree)/arch/x86/include/asm/asm-macros.h: $(obj)/asm-macros.i $(src)/Makefile
	$(call filechk,asm-macros.h)

define filechk_asm-macros.h
    echo '#if 0'; \
    echo '.if 0'; \
    echo '#endif'; \
    echo '#ifndef __ASM_MACROS_H__'; \
    echo '#define __ASM_MACROS_H__'; \
    echo 'asm ( ".include \"$@\"" );'; \
    echo '#endif /* __ASM_MACROS_H__ */'; \
    echo '#if 0'; \
    echo '.endif'; \
    cat $<; \
    echo '#endif'
endef

$(obj)/efi.lds: AFLAGS-y += -DEFI
$(obj)/xen.lds $(obj)/efi.lds: $(src)/xen.lds.S FORCE
	$(call if_changed_dep,cpp_lds_S)

clean-files := \
    include/asm/asm-macros.* \
    $(objtree)/.xen-syms.[0-9]* \
    $(objtree)/.xen.elf32 \
    $(objtree)/.xen.efi.[0-9]* \
    efi/*.efi
