ifneq ($(DOM0_IMAGE),)
builtin_dom0 := y
endif

subdir-$(HAS_PPC64) += powerpc64
subdir-y += papr

obj-y += audit.o
obj-y += backtrace.o
obj-y += bitops.o
obj-y += boot_of.o
obj-y += dart.o
obj-y += dart_u3.o
obj-y += dart_u4.o
obj-y += delay.o
obj-y += dom0_ops.o
obj-y += domain_build.o
obj-y += domain.o
obj-y += exceptions.o
obj-y += external.o
obj-y += float.o
obj-y += hcalls.o
obj-y += htab.o
obj-y += iommu.o
obj-y += irq.o
obj-y += mambo.o
obj-y += memory.o
obj-y += mm.o
obj-y += mpic.o
obj-y += mpic_init.o
obj-y += of-devtree.o
obj-y += of-devwalk.o
obj-y += ofd_fixup.o
obj-y += physdev.o
obj-y += rtas.o
obj-y += setup.o
obj-y += shadow.o
obj-y += smp.o
obj-y += time.o
obj-y += usercopy.o

obj-$(debug) += 0opt.o
obj-$(crash_debug) += gdbstub.o
obj-$(builtin_dom0) += dom0.o

obj-y += firmware_image.o

obj-y += elf32.o

# These are extra warnings like for the arch/ppc directory but may not
# allow the rest of the tree to build.
PPC_C_WARNINGS += -Wundef -Wmissing-prototypes -Wmissing-declarations
PPC_C_WARNINGS += -Wshadow
CFLAGS += $(PPC_C_WARNINGS)

LINK=0x400000
boot32_link_base = $(LINK)
xen_link_offset  = 100
xen_link_base    = $(patsubst %000,%$(xen_link_offset),$(LINK))

#
# The following flags are fed to gcc in order to link several
# objects into a single ELF segment and to not link in any additional
# objects that gcc would normally like to
#
OMAGIC = -N -nodefaultlibs -nostartfiles

firmware: of_handler/built_in.o $(TARGET_SUBARCH)/memcpy.o of-devtree.o
	$(CC) $(CFLAGS) $(OMAGIC) -e __ofh_start -Wl,-Ttext,0x0 $^ -o $@

firmware_image: firmware
	$(CROSS_COMPILE)objcopy --output-target=binary $< $@

firmware_image.o: firmware_image
	$(CROSS_COMPILE)objcopy --input-target=binary \
		--output-target=elf64-powerpc \
		--binary-architecture=powerpc \
		--redefine-sym _binary_$<_start=$(@:%.o=%)_start \
		--redefine-sym _binary_$<_end=$(@:%.o=%)_end \
		--redefine-sym _binary_$<_size=$(@:%.o=%)_size  $< $@

#
# Hacks for included C files
#
irq.o: ../x86/irq.c
physdev.o: ../x86/physdev.c

HDRS += $(wildcard *.h)

# The first token in the arguments will be silently dropped.
IMAGENAME = xen
CMDLINE = ""
boot_of.o: CFLAGS += -DCMDLINE="\"$(IMAGENAME) $(CMDLINE)\""

start.o: boot/start.S
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@

$(TARGET)-syms: start.o $(ALL_OBJS) xen.lds
	$(CC) $(CFLAGS) $(OMAGIC) -Wl,-Ttext,$(xen_link_base),-T,xen.lds start.o $(ALL_OBJS) -o $@

$(TARGET).bin: $(TARGET)-syms
	$(CROSS_COMPILE)objcopy --output-target=binary $< $@

$(TARGET).bin.o: $(TARGET).bin
	$(CROSS_COMPILE)objcopy --input-target=binary \
		--output-target=elf32-powerpc \
		--binary-architecture=powerpc  $< $@

boot32.o: boot/boot32.S
	$(CC) -m32 -Wa,-a32,-mppc64bridge \
		-D__ASSEMBLY__ -D__BRIDGE64__ $(CFLAGS) -c $< -o $@

$(TARGET): boot32.o $(TARGET).bin.o
	$(CC) -m32 -N -Wl,-melf32ppclinux -static -nostdlib \
		-Wl,-Ttext,$(boot32_link_base)  -Wl,-Tdata,$(xen_link_base) \
		$(CFLAGS) $^ -o $@

asm-offsets.s: $(TARGET_SUBARCH)/asm-offsets.c $(HDRS)
	$(CC) $(CFLAGS) -S -o $@ $<

xen.lds: xen.lds.S $(HDRS)
	$(CC) $(CFLAGS) -P -E $(AFLAGS) -o $@ $<

dom0.bin: $(DOM0_IMAGE)
	cp $< $@

clean::
	$(MAKE) -f $(BASEDIR)/Rules.mk -C of_handler clean
	rm -f firmware firmware_image dom0.bin
