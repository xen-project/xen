subdir-$(arm32) += arm32
subdir-$(arm64) += arm64
subdir-y += platforms
subdir-$(arm64) += efi

obj-$(EARLY_PRINTK) += early_printk.o
obj-y += cpu.o
obj-y += domain.o
obj-y += psci.o
obj-y += vpsci.o
obj-y += domctl.o
obj-y += sysctl.o
obj-y += domain_build.o
obj-y += gic.o gic-v2.o
obj-$(CONFIG_ARM_32) += gic-hip04.o
obj-$(HAS_GICV3) += gic-v3.o
obj-y += io.o
obj-y += irq.o
obj-y += kernel.o
obj-y += mm.o
obj-y += p2m.o
obj-y += percpu.o
obj-y += guestcopy.o
obj-y += physdev.o
obj-y += platform.o
obj-y += setup.o
obj-y += bootfdt.o
obj-y += time.o
obj-y += smpboot.o
obj-y += smp.o
obj-y += shutdown.o
obj-y += traps.o
obj-y += vgic.o vgic-v2.o
obj-$(CONFIG_ARM_64) += vgic-v3.o
obj-y += vtimer.o
obj-y += vuart.o
obj-y += hvm.o
obj-y += device.o
obj-y += decode.o
obj-y += processor.o
obj-y += smc.o

#obj-bin-y += ....o

ifdef CONFIG_DTB_FILE
obj-y += dtb.o
AFLAGS += -DCONFIG_DTB_FILE=\"$(CONFIG_DTB_FILE)\"
endif

ALL_OBJS := $(TARGET_SUBARCH)/head.o $(ALL_OBJS)

$(TARGET): $(TARGET)-syms $(TARGET).axf
	$(OBJCOPY) -O binary -S $< $@
ifeq (arm64,$(XEN_TARGET_ARCH))
	ln -sf $(notdir $@)  ../../$(notdir $@).efi
endif

$(TARGET).axf: $(TARGET)-syms
	# XXX: VE model loads by VMA so instead of
	# making a proper ELF we link with LMA == VMA and adjust crudely
	$(OBJCOPY) --change-addresses +0x80000000 $< $@
	$(STRIP) $@

ifeq ($(lto),y)
# Gather all LTO objects together
prelink_lto.o: $(ALL_OBJS)
	$(LD_LTO) -r -o $@ $^

# Link it with all the binary objects
prelink.o: $(patsubst %/built_in.o,%/built_in_bin.o,$(ALL_OBJS)) prelink_lto.o
	$(LD) $(LDFLAGS) -r -o $@ $^
else
prelink.o: $(ALL_OBJS)
	$(LD) $(LDFLAGS) -r -o $@ $^
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

asm-offsets.s: $(TARGET_SUBARCH)/asm-offsets.c
	$(CC) $(filter-out -flto,$(CFLAGS)) -S -o $@ $<

xen.lds: xen.lds.S
	$(CC) -P -E -Ui386 $(AFLAGS) -DXEN_PHYS_START=$(CONFIG_LOAD_ADDRESS) -o $@ $<
	sed -e 's/xen\.lds\.o:/xen\.lds:/g' <.xen.lds.d >.xen.lds.d.new
	mv -f .xen.lds.d.new .xen.lds.d

dtb.o: $(CONFIG_DTB_FILE)

.PHONY: clean
clean::
	rm -f asm-offsets.s xen.lds
	rm -f $(BASEDIR)/.xen-syms.[0-9]*
	rm -f $(TARGET).axf
	rm -f $(TARGET).efi
