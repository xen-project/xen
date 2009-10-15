subdir-y += acpi
subdir-y += cpu
subdir-y += genapic
subdir-y += hvm
subdir-y += mm
subdir-y += oprofile

subdir-$(x86_32) += x86_32
subdir-$(x86_64) += x86_64

obj-y += apic.o
obj-y += bitops.o
obj-y += clear_page.o
obj-y += copy_page.o
obj-y += compat.o
obj-y += delay.o
obj-y += dmi_scan.o
obj-y += domctl.o
obj-y += domain.o
obj-y += domain_build.o
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
obj-y += microcode.o
obj-y += microcode_amd.o
obj-y += microcode_intel.o
obj-y += mm.o
obj-y += mpparse.o
obj-y += nmi.o
obj-y += numa.o
obj-y += pci.o
obj-y += physdev.o
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
obj-y += bzimage.o

obj-$(crash_debug) += gdbstub.o
obj-$(gdbsx) += debug.o

x86_emulate.o: x86_emulate/x86_emulate.c x86_emulate/x86_emulate.h

$(TARGET): $(TARGET)-syms boot/mkelf32
	./boot/mkelf32 $(TARGET)-syms $(TARGET) 0x100000 \
	`$(NM) -nr $(TARGET)-syms | head -n 1 | sed -e 's/^\([^ ]*\).*/0x\1/'`

ALL_OBJS := $(BASEDIR)/arch/x86/boot/built_in.o $(ALL_OBJS)

$(TARGET)-syms: $(ALL_OBJS) xen.lds
	$(MAKE) -f $(BASEDIR)/Rules.mk $(BASEDIR)/common/symbols-dummy.o
	$(LD) $(LDFLAGS) -T xen.lds -N $(ALL_OBJS) \
	    $(BASEDIR)/common/symbols-dummy.o -o $(@D)/.$(@F).0
	$(NM) -n $(@D)/.$(@F).0 | $(BASEDIR)/tools/symbols >$(@D)/.$(@F).0.S
	$(MAKE) -f $(BASEDIR)/Rules.mk $(@D)/.$(@F).0.o
	$(LD) $(LDFLAGS) -T xen.lds -N $(ALL_OBJS) \
	    $(@D)/.$(@F).0.o -o $(@D)/.$(@F).1
	$(NM) -n $(@D)/.$(@F).1 | $(BASEDIR)/tools/symbols >$(@D)/.$(@F).1.S
	$(MAKE) -f $(BASEDIR)/Rules.mk $(@D)/.$(@F).1.o
	$(LD) $(LDFLAGS) -T xen.lds -N $(ALL_OBJS) \
	    $(@D)/.$(@F).1.o -o $@
	rm -f $(@D)/.$(@F).[0-9]*

asm-offsets.s: $(TARGET_SUBARCH)/asm-offsets.c
	$(CC) $(CFLAGS) -S -o $@ $<

xen.lds: xen.lds.S
	$(CC) -P -E -Ui386 $(AFLAGS) -o $@ $<
	sed -e 's/xen\.lds\.o:/xen\.lds:/g' <.xen.lds.d >.xen.lds.d.new
	mv -f .xen.lds.d.new .xen.lds.d

boot/mkelf32: boot/mkelf32.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

.PHONY: clean
clean::
	rm -f asm-offsets.s xen.lds boot/*.o boot/*~ boot/core boot/mkelf32
	rm -f $(BASEDIR)/.xen-syms.[0-9]* boot/.*.d
	rm -f boot/reloc.S boot/reloc.lnk boot/reloc.bin
