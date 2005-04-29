include $(BASEDIR)/Rules.mk

# libs-y	+= arch/ia64/lib/lib.a

OBJS = xensetup.o setup.o time.o irq.o ia64_ksyms.o process.o smp.o \
	xenmisc.o pdb-stub.o acpi.o hypercall.o \
	machvec.o dom0_ops.o domain.o \
	idle0_task.o pal.o hpsim.o efi.o efi_stub.o ivt.o mm_contig.o \
	xenmem.o sal.o cmdline.o mm_init.o tlb.o smpboot.o \
	extable.o linuxextable.o xenirq.o \
	regionreg.o entry.o unaligned.o privop.o vcpu.o \
	irq_ia64.o irq_lsapic.o vhpt.o xenasm.o dom_fw.o
# perfmon.o
# unwind.o needed for kernel unwinding (rare)

OBJS := $(subst $(TARGET_ARCH)/asm-offsets.o,,$(OBJS))

# remove following line if not privifying in memory
# OBJS += privify.o

default: $(OBJS) head.o ia64lib.o xen.lds.s
	$(LD) -r -o arch.o $(OBJS) ia64lib.o
	$(LD) $(LDFLAGS) -T $(BASEDIR)/arch/$(TARGET_ARCH)/xen.lds.s -N \
		-Map map.out head.o $(ALL_OBJS) -o $(TARGET)-syms
	$(OBJCOPY) -R .note -R .comment -S $(TARGET)-syms $(TARGET)

asm-offsets.s: asm-offsets.c
	$(CC) $(CFLAGS) -S -o $@ $<

# I'm sure a Makefile wizard would know a better way to do this
xen.lds.s: xen.lds.S
	$(CC) -E $(CPPFLAGS) -P -DXEN -D__ASSEMBLY__ \
		-o xen.lds.s xen.lds.S

ia64lib.o:
	$(MAKE) -C lib && cp lib/ia64lib.o .

clean:
	rm -f *.o *~ core  xen.lds.s $(BASEDIR)/include/asm-ia64/.offsets.h.stamp
	rm -f lib/*.o

# setup.o contains bits of compile.h so it must be blown away
delete-unfresh-files:
	echo any unfresh-files to delete for ia64\?
#	rm -f setup.o

.PHONY: default clean delete-unfresh-files

