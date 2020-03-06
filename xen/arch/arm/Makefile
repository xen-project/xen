obj-$(CONFIG_ARM_32) += arm32/
obj-$(CONFIG_ARM_64) += arm64/
obj-$(CONFIG_ARM_64) += efi/
obj-$(CONFIG_ACPI) += acpi/
ifneq ($(CONFIG_NO_PLAT),y)
obj-y += platforms/
endif
obj-$(CONFIG_TEE) += tee/

obj-$(CONFIG_HAS_ALTERNATIVE) += alternative.o
obj-y += bootfdt.init.o
obj-y += cpuerrata.o
obj-y += cpufeature.o
obj-y += decode.o
obj-y += device.o
obj-y += domain.o
obj-y += domain_build.init.o
obj-y += domctl.o
obj-$(EARLY_PRINTK) += early_printk.o
obj-y += gic.o
obj-y += gic-v2.o
obj-$(CONFIG_GICV3) += gic-v3.o
obj-$(CONFIG_HAS_ITS) += gic-v3-its.o
obj-$(CONFIG_HAS_ITS) += gic-v3-lpi.o
obj-y += guestcopy.o
obj-y += guest_atomics.o
obj-y += guest_walk.o
obj-y += hvm.o
obj-y += io.o
obj-y += irq.o
obj-y += kernel.init.o
obj-$(CONFIG_LIVEPATCH) += livepatch.o
obj-y += mem_access.o
obj-y += mm.o
obj-y += monitor.o
obj-y += p2m.o
obj-y += percpu.o
obj-y += platform.o
obj-y += platform_hypercall.o
obj-y += physdev.o
obj-y += processor.o
obj-y += psci.o
obj-y += setup.o
obj-y += shutdown.o
obj-y += smp.o
obj-y += smpboot.o
obj-y += sysctl.o
obj-y += time.o
obj-y += traps.o
obj-y += vcpreg.o
obj-$(CONFIG_NEW_VGIC) += vgic/
ifneq ($(CONFIG_NEW_VGIC),y)
obj-y += gic-vgic.o
obj-y += vgic.o
obj-y += vgic-v2.o
obj-$(CONFIG_GICV3) += vgic-v3.o
obj-$(CONFIG_HAS_ITS) += vgic-v3-its.o
endif
obj-y += vm_event.o
obj-y += vtimer.o
obj-$(CONFIG_SBSA_VUART_CONSOLE) += vpl011.o
obj-y += vsmc.o
obj-y += vpsci.o
obj-y += vuart.o

#obj-bin-y += ....o

ifdef CONFIG_DTB_FILE
obj-y += dtb.o
AFLAGS += -DCONFIG_DTB_FILE=\"$(CONFIG_DTB_FILE)\"
endif

ALL_OBJS := $(TARGET_SUBARCH)/head.o $(ALL_OBJS)

DEPS += $(TARGET_SUBARCH)/.head.o.d

ifdef CONFIG_LIVEPATCH
all_symbols = --all-symbols
ifdef CONFIG_FAST_SYMBOL_LOOKUP
all_symbols = --all-symbols --sort-by-name
endif
else
all_symbols =
endif

$(TARGET): $(TARGET)-syms
	$(OBJCOPY) -O binary -S $< $@
ifeq ($(CONFIG_ARM_64),y)
	ln -sf $(notdir $@)  ../../$(notdir $@).efi
endif

ifeq ($(CONFIG_LTO),y)
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

$(TARGET)-syms: prelink.o xen.lds
	$(LD) $(LDFLAGS) -T xen.lds -N prelink.o \
	    $(BASEDIR)/common/symbols-dummy.o -o $(@D)/.$(@F).0
	$(NM) -pa --format=sysv $(@D)/.$(@F).0 \
		| $(BASEDIR)/tools/symbols $(all_symbols) --sysv --sort >$(@D)/.$(@F).0.S
	$(MAKE) -f $(BASEDIR)/Rules.mk $(@D)/.$(@F).0.o
	$(LD) $(LDFLAGS) -T xen.lds -N prelink.o \
	    $(@D)/.$(@F).0.o -o $(@D)/.$(@F).1
	$(NM) -pa --format=sysv $(@D)/.$(@F).1 \
		| $(BASEDIR)/tools/symbols $(all_symbols) --sysv --sort >$(@D)/.$(@F).1.S
	$(MAKE) -f $(BASEDIR)/Rules.mk $(@D)/.$(@F).1.o
	$(LD) $(LDFLAGS) -T xen.lds -N prelink.o $(build_id_linker) \
	    $(@D)/.$(@F).1.o -o $@
	$(NM) -pa --format=sysv $(@D)/$(@F) \
		| $(BASEDIR)/tools/symbols --xensyms --sysv --sort \
		>$(@D)/$(@F).map
	rm -f $(@D)/.$(@F).[0-9]*

asm-offsets.s: $(TARGET_SUBARCH)/asm-offsets.c
	$(CC) $(filter-out -flto,$(CFLAGS)) -S -o $@ $<

xen.lds: xen.lds.S
	$(CC) -P -E -Ui386 $(AFLAGS) -o $@ $<
	sed -e 's/xen\.lds\.o:/xen\.lds:/g' <.xen.lds.d >.xen.lds.d.new
	mv -f .xen.lds.d.new .xen.lds.d

dtb.o: $(CONFIG_DTB_FILE)

.PHONY: clean
clean::
	rm -f asm-offsets.s xen.lds
	rm -f $(BASEDIR)/.xen-syms.[0-9]*
	rm -f $(TARGET).efi
