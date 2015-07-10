subdir-y += acpi
subdir-y += cpu
subdir-y += genapic
subdir-y += hvm
subdir-y += mm
subdir-y += oprofile

subdir-$(x86_64) += x86_64

obj-bin-y += alternative.init.o
obj-y += apic.o
obj-y += bitops.o
obj-bin-y += bzimage.init.o
obj-bin-y += clear_page.o
obj-bin-y += copy_page.o
obj-y += compat.o
obj-y += debug.o
obj-y += delay.o
obj-bin-y += dmi_scan.init.o
obj-y += domctl.o
obj-y += domain.o
obj-bin-y += domain_build.init.o
obj-y += domain_page.o
obj-y += e820.o
obj-y += extable.o
obj-y += flushtlb.o
obj-y += platform_hypercall.o
obj-y += i387.o
obj-y += i8259.o
obj-y += io_apic.o
obj-y += msi.o
obj-y += ioport_emulate.o
obj-y += irq.o
obj-y += microcode_amd.o
obj-y += microcode_intel.o
# This must come after the vendor specific files.
obj-y += microcode.o
obj-y += mm.o
obj-y += monitor.o
obj-y += mpparse.o
obj-y += nmi.o
obj-y += numa.o
obj-y += pci.o
obj-y += percpu.o
obj-y += physdev.o
obj-y += psr.o
obj-y += setup.o
obj-y += shutdown.o
obj-y += smp.o
obj-y += smpboot.o
obj-y += srat.o
obj-y += string.o
obj-y += sysctl.o
obj-y += time.o
obj-y += trace.o
obj-y += traps.o
obj-y += usercopy.o
obj-y += x86_emulate.o
obj-y += machine_kexec.o
obj-y += crash.o
obj-y += tboot.o
obj-y += hpet.o
obj-y += vm_event.o
obj-y += xstate.o

obj-$(crash_debug) += gdbstub.o

x86_emulate.o: x86_emulate/x86_emulate.c x86_emulate/x86_emulate.h

efi-$(x86_64) := $(shell if [ ! -r $(BASEDIR)/include/xen/compile.h -o \
                                -O $(BASEDIR)/include/xen/compile.h ]; then \
                         echo '$(TARGET).efi'; fi)

$(TARGET): $(TARGET)-syms $(efi-y) boot/mkelf32
	./boot/mkelf32 $(TARGET)-syms $(TARGET) 0x100000 \
	`$(NM) -nr $(TARGET)-syms | head -n 1 | sed -e 's/^\([^ ]*\).*/0x\1/'`


ALL_OBJS := $(BASEDIR)/arch/x86/boot/built_in.o $(BASEDIR)/arch/x86/efi/built_in.o $(ALL_OBJS)

ifeq ($(lto),y)
# Gather all LTO objects together
prelink_lto.o: $(ALL_OBJS)
	$(LD_LTO) -r -o $@ $^

prelink-efi_lto.o: $(ALL_OBJS) efi/runtime.o efi/compat.o
	$(guard) $(LD_LTO) -r -o $@ $(filter-out %/efi/built_in.o,$^)

# Link it with all the binary objects
prelink.o: $(patsubst %/built_in.o,%/built_in_bin.o,$(ALL_OBJS)) prelink_lto.o
	$(LD) $(LDFLAGS) -r -o $@ $^

prelink-efi.o: $(patsubst %/built_in.o,%/built_in_bin.o,$(ALL_OBJS)) prelink-efi_lto.o efi/boot.init.o
	$(guard) $(LD) $(LDFLAGS) -r -o $@ $^
else
prelink.o: $(ALL_OBJS)
	$(LD) $(LDFLAGS) -r -o $@ $^

prelink-efi.o: $(ALL_OBJS) efi/boot.init.o efi/runtime.o efi/compat.o
	$(guard) $(LD) $(LDFLAGS) -r -o $@ $(filter-out %/efi/built_in.o,$^)
endif

$(BASEDIR)/common/symbols-dummy.o:
	$(MAKE) -f $(BASEDIR)/Rules.mk -C $(BASEDIR)/common symbols-dummy.o

$(TARGET)-syms: prelink.o xen.lds $(BASEDIR)/common/symbols-dummy.o
	$(LD) $(LDFLAGS) -T xen.lds -N prelink.o \
	    $(BASEDIR)/common/symbols-dummy.o -o $(@D)/.$(@F).0
	$(NM) -n $(@D)/.$(@F).0 | $(BASEDIR)/tools/symbols >$(@D)/.$(@F).0.S
	$(MAKE) -f $(BASEDIR)/Rules.mk $(@D)/.$(@F).0.o
	$(LD) $(LDFLAGS) -T xen.lds -N prelink.o \
	    $(@D)/.$(@F).0.o -o $(@D)/.$(@F).1
	$(NM) -n $(@D)/.$(@F).1 | $(BASEDIR)/tools/symbols >$(@D)/.$(@F).1.S
	$(MAKE) -f $(BASEDIR)/Rules.mk $(@D)/.$(@F).1.o
	$(LD) $(LDFLAGS) -T xen.lds -N prelink.o \
	    $(@D)/.$(@F).1.o -o $@
	rm -f $(@D)/.$(@F).[0-9]*

EFI_LDFLAGS = $(patsubst -m%,-mi386pep,$(LDFLAGS)) --subsystem=10
EFI_LDFLAGS += --image-base=$(1) --stack=0,0 --heap=0,0 --strip-debug
EFI_LDFLAGS += --section-alignment=0x200000 --file-alignment=0x20
EFI_LDFLAGS += --major-image-version=$(XEN_VERSION)
EFI_LDFLAGS += --minor-image-version=$(XEN_SUBVERSION)
EFI_LDFLAGS += --major-os-version=2 --minor-os-version=0
EFI_LDFLAGS += --major-subsystem-version=2 --minor-subsystem-version=0

$(TARGET).efi: VIRT_BASE = 0x$(shell $(NM) efi/relocs-dummy.o | sed -n 's, A VIRT_START$$,,p')
$(TARGET).efi: ALT_BASE = 0x$(shell $(NM) efi/relocs-dummy.o | sed -n 's, A ALT_START$$,,p')
# Don't use $(wildcard ...) here - at least make 3.80 expands this too early!
$(TARGET).efi: guard = $(if $(shell echo efi/dis* | grep disabled),:)
$(TARGET).efi: prelink-efi.o efi.lds efi/relocs-dummy.o $(BASEDIR)/common/symbols-dummy.o efi/mkreloc
	$(foreach base, $(VIRT_BASE) $(ALT_BASE), \
	          $(guard) $(LD) $(call EFI_LDFLAGS,$(base)) -T efi.lds -N $< efi/relocs-dummy.o \
	                $(BASEDIR)/common/symbols-dummy.o -o $(@D)/.$(@F).$(base).0 &&) :
	$(guard) efi/mkreloc $(foreach base,$(VIRT_BASE) $(ALT_BASE),$(@D)/.$(@F).$(base).0) >$(@D)/.$(@F).0r.S
	$(guard) $(NM) -n $(@D)/.$(@F).$(VIRT_BASE).0 | $(guard) $(BASEDIR)/tools/symbols >$(@D)/.$(@F).0s.S
	$(guard) $(MAKE) -f $(BASEDIR)/Rules.mk $(@D)/.$(@F).0r.o $(@D)/.$(@F).0s.o
	$(foreach base, $(VIRT_BASE) $(ALT_BASE), \
	          $(guard) $(LD) $(call EFI_LDFLAGS,$(base)) -T efi.lds -N $< \
	                $(@D)/.$(@F).0r.o $(@D)/.$(@F).0s.o -o $(@D)/.$(@F).$(base).1 &&) :
	$(guard) efi/mkreloc $(foreach base,$(VIRT_BASE) $(ALT_BASE),$(@D)/.$(@F).$(base).1) >$(@D)/.$(@F).1r.S
	$(guard) $(NM) -n $(@D)/.$(@F).$(VIRT_BASE).1 | $(guard) $(BASEDIR)/tools/symbols >$(@D)/.$(@F).1s.S
	$(guard) $(MAKE) -f $(BASEDIR)/Rules.mk $(@D)/.$(@F).1r.o $(@D)/.$(@F).1s.o
	$(guard) $(LD) $(call EFI_LDFLAGS,$(VIRT_BASE)) -T efi.lds -N $< \
	                $(@D)/.$(@F).1r.o $(@D)/.$(@F).1s.o -o $@
	if $(guard) false; then rm -f $@; echo 'EFI support disabled'; fi
	rm -f $(@D)/.$(@F).[0-9]*

efi/boot.init.o efi/runtime.o efi/compat.o: $(BASEDIR)/arch/x86/efi/built_in.o
efi/boot.init.o efi/runtime.o efi/compat.o: ;

asm-offsets.s: $(TARGET_SUBARCH)/asm-offsets.c
	$(CC) $(filter-out -flto,$(CFLAGS)) -S -o $@ $<

xen.lds: xen.lds.S
	$(CC) -P -E -Ui386 $(AFLAGS) -o $@ $<
	sed -e 's/xen\.lds\.o:/xen\.lds:/g' <.xen.lds.d >.xen.lds.d.new
	mv -f .xen.lds.d.new .xen.lds.d

efi.lds: xen.lds.S
	$(CC) -P -E -Ui386 -DEFI $(AFLAGS) -o $@ $<
	sed -e 's/efi\.lds\.o:/efi\.lds:/g' <.$(@F).d >.$(@F).d.new
	mv -f .$(@F).d.new .$(@F).d

boot/mkelf32: boot/mkelf32.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

efi/mkreloc: efi/mkreloc.c
	$(HOSTCC) $(HOSTCFLAGS) -g -o $@ $<

.PHONY: clean
clean::
	rm -f asm-offsets.s *.lds boot/*.o boot/*~ boot/core boot/mkelf32
	rm -f $(BASEDIR)/.xen-syms.[0-9]* boot/.*.d
	rm -f $(BASEDIR)/.xen.efi.[0-9]* efi/*.o efi/.*.d efi/*.efi efi/disabled efi/mkreloc
	rm -f boot/reloc.S boot/reloc.lnk boot/reloc.bin
