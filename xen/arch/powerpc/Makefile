ifneq ($(DOM0_IMAGE),)
builtin_dom0 := y
endif

subdir-$(HAS_PPC64) += powerpc64
subdir-y += papr

obj-y += audit.o
obj-y += backtrace.o
obj-y += bitops.o
obj-y += boot_of.o
obj-y += cmdline.o
obj-y += dart.o
obj-y += dart_u3.o
obj-y += dart_u4.o
obj-y += domctl.o
obj-y += domain_build.o
obj-y += domain.o
obj-y += exceptions.o
obj-y += external.o
obj-y += float.o
obj-y += hcalls.o
obj-y += iommu.o
obj-y += irq.o
obj-y += systemsim.o
obj-y += memory.o
obj-y += mm.o
obj-y += mpic.o
obj-y += mpic_init.o
obj-y += numa.o
obj-y += of-devtree.o
obj-y += of-devwalk.o
obj-y += ofd_fixup.o
obj-y += ofd_fixup_memory.o
obj-y += physdev.o
obj-y += platform.o
obj-y += rtas.o
obj-y += setup.o
obj-y += shadow.o
obj-y += smp.o
obj-y += smpboot.o
obj-y += smp-tbsync.o
obj-y += sysctl.o
obj-y += time.o
obj-y += usercopy.o
obj-y += machine_kexec.o
obj-y += crash.o

obj-$(debug) += 0opt.o
obj-$(crash_debug) += gdbstub.o
obj-$(builtin_dom0) += dom0.o

obj-y += firmware_image.o

# These are extra warnings like for the arch/ppc directory but may not
# allow the rest of the tree to build.
PPC_C_WARNINGS += -Wundef -Wmissing-prototypes -Wmissing-declarations
PPC_C_WARNINGS += -Wshadow
CFLAGS += $(PPC_C_WARNINGS)

#
# The following flags are fed to gcc in order to link several
# objects into a single ELF segment and to not link in any additional
# objects that gcc would normally like to
#
OMAGIC = -nodefaultlibs -nostartfiles

firmware: of_handler/built_in.o $(TARGET_SUBARCH)/memcpy.o of-devtree.o
	$(CC) $(CFLAGS) $(OMAGIC) -e __ofh_start -Wl,-Ttext,0x0 $^ -o $@

firmware_image.bin: firmware
	$(CROSS_COMPILE)objcopy --output-target=binary $< $@

#
# Hacks for included C files
#
irq.o: ../x86/irq.c
physdev.o: ../x86/physdev.c
numa.o: ../x86/numa.c

HDRS += $(wildcard *.h)

ifneq ($(CMDLINE),)
# The first token in the arguments will be silently dropped.
FULL_CMDLINE := xen $(CMDLINE)
endif

ifeq ($(wildcard cmdline.dep),)
cmdline.dep:
	echo $(FULL_CMDLINE) > cmdline.dep
else
ifneq ($(FULL_CMDLINE),$(shell cat cmdline.dep))
cmdline.dep::
	echo $(FULL_CMDLINE) > cmdline.dep
else
cmdline.dep:
endif
endif

cmdline.o: cmdline.dep
cmdline.o: CFLAGS += -DCMDLINE="\"$(FULL_CMDLINE)\""

TARGET_OPTS = $(OMAGIC) -Wl,-T,xen.lds
TARGET_OPTS += start.o $(ALL_OBJS)

.xen-syms: start.o $(ALL_OBJS) xen.lds
	$(MAKE) -f $(BASEDIR)/Rules.mk $(BASEDIR)/common/symbols-dummy.o
	$(CC) $(CFLAGS) $(TARGET_OPTS) $(BASEDIR)/common/symbols-dummy.o -o $@

NM=$(CROSS_COMPILE)nm
new_nm := $(shell if $(NM) --help 2>&1 | grep -- '--synthetic' > /dev/null; then echo y; else echo n; fi)

ifeq ($(new_nm),y)
NM		:= $(NM) --synthetic
endif

xen-syms.S: .xen-syms
	$(NM) -n $^ | $(BASEDIR)/tools/symbols > $@

xen-syms.o: xen-syms.S
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@

$(TARGET)-syms: start.o $(ALL_OBJS) xen-syms.o xen.lds
	$(CC) $(CFLAGS) $(TARGET_OPTS) xen-syms.o -o $@

# our firmware only loads 32-bit ELF files
OCPYFLAGS := --input-target=elf64-powerpc --output-target=elf32-powerpc
$(TARGET): $(TARGET)-syms
	$(CROSS_COMPILE)objcopy $(OCPYFLAGS) $^ $@

asm-offsets.s: $(TARGET_SUBARCH)/asm-offsets.c $(HDRS)
	$(CC) $(CFLAGS) -S -o $@ $<

xen.lds: xen.lds.S $(HDRS)
	$(CC) -P -E $(AFLAGS) -o $@ $<

dom0.bin: $(DOM0_IMAGE)
	cp $< $@

clean::
	$(MAKE) -f $(BASEDIR)/Rules.mk -C of_handler clean
	rm -f firmware firmware_image.bin dom0.bin .xen-syms xen-syms.S \
		xen.lds asm-offsets.s cmdline.dep
