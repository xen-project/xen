subdir-y += acpi
subdir-y += cpu
subdir-y += genapic
subdir-y += hvm

subdir-$(x86_32) += x86_32
subdir-$(x86_64) += x86_64

obj-y += apic.o
obj-y += audit.o
obj-y += bitops.o
obj-y += delay.o
obj-y += dmi_scan.o
obj-y += dom0_ops.o
obj-y += domain.o
obj-y += domain_build.o
obj-y += e820.o
obj-y += extable.o
obj-y += flushtlb.o
obj-y += i387.o
obj-y += i8259.o
obj-y += io_apic.o
obj-y += irq.o
obj-y += microcode.o
obj-y += mm.o
obj-y += mpparse.o
obj-y += nmi.o
obj-y += physdev.o
obj-y += rwlock.o
obj-y += setup.o
obj-y += shutdown.o
obj-y += smp.o
obj-y += smpboot.o
obj-y += string.o
obj-y += time.o
obj-y += trampoline.o
obj-y += traps.o
obj-y += usercopy.o
obj-y += x86_emulate.o

ifneq ($(pae),n)
obj-$(x86_32) += shadow.o shadow_public.o shadow_guest32.o
else
obj-$(x86_32) += shadow32.o
endif

obj-$(x86_64) += shadow.o shadow_public.o shadow_guest32.o shadow_guest32pae.o

obj-$(crash_debug) += gdbstub.o

$(TARGET): $(TARGET)-syms boot/mkelf32
	./boot/mkelf32 $(TARGET)-syms $(TARGET) 0x100000 \
	`$(NM) $(TARGET)-syms | sort | tail -n 1 | sed -e 's/^\([^ ]*\).*/0x\1/'`

$(TARGET)-syms: boot/$(TARGET_SUBARCH).o $(ALL_OBJS) xen.lds
	$(LD) $(LDFLAGS) -T xen.lds -N \
	    boot/$(TARGET_SUBARCH).o $(ALL_OBJS) -o $@
	$(NM) -n $@ | $(BASEDIR)/tools/symbols >$(BASEDIR)/xen-syms.S
	$(MAKE) -f $(BASEDIR)/Rules.mk $(BASEDIR)/xen-syms.o
	$(LD) $(LDFLAGS) -T xen.lds -N \
	    boot/$(TARGET_SUBARCH).o $(ALL_OBJS) $(BASEDIR)/xen-syms.o -o $@
	$(NM) -n $@ | $(BASEDIR)/tools/symbols >$(BASEDIR)/xen-syms.S
	$(MAKE) -f $(BASEDIR)/Rules.mk $(BASEDIR)/xen-syms.o
	$(LD) $(LDFLAGS) -T xen.lds -N \
	    boot/$(TARGET_SUBARCH).o $(ALL_OBJS) $(BASEDIR)/xen-syms.o -o $@
	rm -f $(BASEDIR)/xen-syms.S $(BASEDIR)/xen-syms.o

asm-offsets.s: $(TARGET_SUBARCH)/asm-offsets.c $(HDRS)
	$(CC) $(CFLAGS) -S -o $@ $<

xen.lds: $(TARGET_SUBARCH)/xen.lds.S $(HDRS)
	$(CC) $(CFLAGS) -P -E -Ui386 $(AFLAGS) -o $@ $<

boot/mkelf32: boot/mkelf32.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

shadow_guest32.o: shadow.c

clean:: FORCE
	rm -f asm-offsets.s xen.lds boot/*.o boot/*~ boot/core boot/mkelf32
