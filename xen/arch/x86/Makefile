# Put this ahead of the sorted list below, as it takes long to build and hence
# we'd like parallel make to schedule its building early.
obj-y += x86_emulate/

obj-y += acpi/
obj-y += boot/
obj-y += cpu/
obj-y += efi/
obj-y += genapic/
obj-$(CONFIG_GUEST) += guest/
obj-$(CONFIG_HVM) += hvm/
obj-y += lib/
obj-y += mm/
obj-$(CONFIG_PV) += pv/
obj-y += x86_64/

obj-y += alternative.o
obj-y += apic.o
obj-y += bhb-thunk.o
obj-y += bitops.o
obj-bin-y += bzimage.init.o
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
obj-y += hpet.o
obj-y += hypercall.o
obj-y += i387.o
obj-y += i8259.o
obj-$(CONFIG_INDIRECT_THUNK) += indirect-thunk.o
obj-$(CONFIG_RETURN_THUNK) += indirect-thunk.o
obj-$(CONFIG_PV) += ioport_emulate.o
obj-y += io_apic.o
obj-y += irq.o
obj-$(CONFIG_LIVEPATCH) += livepatch.o
obj-$(CONFIG_KEXEC) += machine_kexec.o
obj-y += mm.o x86_64/mm.o
obj-$(CONFIG_VM_EVENT) += monitor.o
obj-y += mpparse.o
obj-y += msi.o
obj-y += msr.o
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
obj-$(CONFIG_SYSCTL) += sysctl.o
obj-$(CONFIG_TBOOT) += tboot.o
obj-y += time.o
obj-y += traps-setup.o
obj-y += traps.o
obj-$(CONFIG_INTEL) += tsx.o
obj-$(CONFIG_VM_EVENT) += vm_event.o
obj-y += xstate.o

ifneq ($(CONFIG_PV_SHIM_EXCLUSIVE),y)
obj-y += domctl.o
obj-y += platform_hypercall.o
obj-$(CONFIG_COMPAT) += x86_64/platform_hypercall.o
endif

extra-y += asm-macros.i
extra-y += xen.lds

hostprogs-y += boot/mkelf32
hostprogs-y += efi/mkreloc

$(obj)/efi/mkreloc: HOSTCFLAGS += -I$(srctree)/include

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

$(TARGET): TMP = $(dot-target).elf32
$(TARGET): $(TARGET)-syms $(efi-y) $(obj)/boot/mkelf32
	$(obj)/boot/mkelf32 $(notes_phdrs) $(TARGET)-syms $(TMP) $(XEN_IMG_OFFSET)
	od -t x4 -N 8192 $(TMP)  | grep 1badb002 > /dev/null || \
		{ echo "No Multiboot1 header found" >&2; false; }
	od -t x4 -N 32768 $(TMP) | grep e85250d6 > /dev/null || \
		{ echo "No Multiboot2 header found" >&2; false; }
	mv $(TMP) $(TARGET)

CFLAGS-$(XEN_BUILD_EFI) += -DXEN_BUILD_EFI

LAST_LINKING_PASS := 2

final-image-check-$(CONFIG_XEN_IBT) = $(SHELL) $(srctree)/tools/check-endbr.sh $(1)

include scripts/Makefile.link

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

.INTERMEDIATE: $(addprefix .$(TARGET).efi., \
                           $(foreach n, 0 1 2, \
                                     $(n) alt.$(n) $(n)r.o $(n)s.o $(n)r.S $(n)s.S))

.$(TARGET).efi.%.o: .$(TARGET).efi.%.S
	$(call cmd,cc_o_S)

.$(TARGET).efi.1r.S: .$(TARGET).efi.0 $(if $(relocs-dummy),.$(TARGET).efi.alt.0)
.$(TARGET).efi.2r.S: .$(TARGET).efi.1 $(if $(relocs-dummy),.$(TARGET).efi.alt.1)

.$(TARGET).efi.0r.o: $(obj)/efi/relocs-dummy.o
	ln -sf $< $@

.$(TARGET).efi.%r.S: $(obj)/efi/mkreloc
	$(MKRELOC) $(filter .$(TARGET).efi.%, $^) > $@

.$(TARGET).efi.0s.S:
	$(objtree)/tools/symbols $(all_symbols) --empty > $@

.$(TARGET).efi.1s.S: .$(TARGET).efi.0
.$(TARGET).efi.2s.S: .$(TARGET).efi.1

.$(TARGET).efi.%s.S:
	$(NM) -pa --format=sysv $< \
	  | $(objtree)/tools/symbols $(all_symbols) --sysv --sort \
 	    --source-name=$(TARGET).efi.S \
	  > $@

# See above for why $(note_file) needs removing here.
efi-objs = $(filter-out $(note_file),$(filter %.o,$^))

.$(TARGET).efi.%: $(objtree)/prelink.o .$(TARGET).efi.%r.o \
                  .$(TARGET).efi.%s.o $(note_file) $(obj)/efi.lds
	$(LD) $(call EFI_LDFLAGS,$(VIRT_BASE)) -T $(obj)/efi.lds $(efi-objs) \
	      --strip-debug $(note_file_option) -o $@

.$(TARGET).efi.alt.%: $(objtree)/prelink.o .$(TARGET).efi.%r.o \
                      .$(TARGET).efi.%s.o $(note_file) $(obj)/efi.lds
	$(LD) $(call EFI_LDFLAGS,$(ALT_BASE)) -T $(obj)/efi.lds $(efi-objs) \
	      --strip-debug $(note_file_option) -o $@

.$(TARGET).efi.2: $(objtree)/prelink.o $(obj)/efi/relocs-empty.o \
                  .$(TARGET).efi.2r.o .$(TARGET).efi.2s.o $(note_file) \
                  $(obj)/efi.lds
	$(call compare-symbol-tables, .$(TARGET).efi.1r.o, .$(TARGET).efi.2r.o)
	$(call compare-symbol-tables, .$(TARGET).efi.1s.o, .$(TARGET).efi.2s.o)
	$(LD) $(call EFI_LDFLAGS,$(VIRT_BASE)) -T $(obj)/efi.lds $(efi-objs) \
	      $(orphan-handling-y) $(note_file_option) -o $@

$(TARGET).efi: .$(TARGET).efi.2
ifeq ($(CONFIG_DEBUG_INFO),y)
	$(if $(filter --strip-debug,$(EFI_LDFLAGS)),echo,:) "No debug info in $(@F)"
endif
	$(NM) -pa --format=sysv $< \
	  | $(objtree)/tools/symbols --all-symbols --xensyms --sysv --sort \
	  > $@.map
ifeq ($(CONFIG_DEBUG_INFO),y)
	$(if $(filter --strip-debug,$(EFI_LDFLAGS)),:$(space))$(OBJCOPY) -O elf64-x86-64 $< $@.elf
endif
	$(call final-image-check-y, $<)
	mv $< $@
	rm -f $(dot-target).[0-9]* $(@D)/..$(@F).[0-9]*
else
$(TARGET).efi: FORCE
	rm -f $@
	echo '$(if $(filter y,$(XEN_BUILD_EFI)),xen.efi generation,EFI support) disabled'
endif

# These should already have been rebuilt when building the prerequisite of "prelink.o"
$(obj)/efi/buildid.o $(obj)/efi/relocs-dummy.o $(obj)/efi/relocs-empty.o: ;

.PHONY: include
include: $(objtree)/arch/x86/include/asm/asm-macros.h

$(obj)/asm-macros.i: CFLAGS-y += -P

$(objtree)/arch/x86/include/asm/asm-macros.h: $(obj)/asm-macros.i $(src)/Makefile
	$(call filechk,asm-macros.h)

define filechk_asm-macros.h
    echo '#ifndef X86_MACROS_H'; \
    echo '#define X86_MACROS_H'; \
    echo '#if 0'; \
    echo '.if 0'; \
    echo '#endif'; \
    echo 'asm ( ".include \"$@\"" );'; \
    echo '#if 0'; \
    echo '.endif'; \
    cat $<; \
    echo '#endif'; \
    echo '#endif /* X86_MACROS_H */'
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
