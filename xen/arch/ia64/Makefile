include $(BASEDIR)/Rules.mk

VPATH = xen vmx linux linux-xen

OBJS = xensetup.o setup.o time.o irq.o process.o smp.o \
	xenmisc.o acpi.o hypercall.o \
	machvec.o dom0_ops.o domain.o hpsimserial.o pcdp.o \
	idle0_task.o pal.o hpsim.o efi.o efi_stub.o ivt.o mm_contig.o \
	xenmem.o sal.o cmdline.o mm_init.o tlb.o smpboot.o \
	extable.o linuxextable.o sort.o xenirq.o xentime.o \
	regionreg.o entry.o unaligned.o privop.o vcpu.o \
	irq_ia64.o irq_lsapic.o vhpt.o xenasm.o hyperprivop.o dom_fw.o \
	sn_console.o # ia64_ksyms.o 

OBJS += vmx_init.o vmx_virt.o vmx_vcpu.o vmx_process.o vmx_vsa.o vmx_ivt.o\
	vmx_phy_mode.o vmx_utility.o vmx_interrupt.o vmx_entry.o vmmu.o \
	vtlb.o mmio.o vlsapic.o vmx_hypercall.o mm.o vmx_support.o \
	pal_emul.o vmx_irq_ia64.o vmx_vioapic.o

# lib files from xen/arch/ia64/linux/ (linux/arch/ia64/lib)
OBJS +=	bitop.o clear_page.o flush.o copy_page_mck.o			\
	memset.o strlen.o memcpy_mck.o 					\
	__divsi3.o __udivsi3.o __modsi3.o __umodsi3.o			\
	__divdi3.o __udivdi3.o __moddi3.o __umoddi3.o

# perfmon.o
# unwind.o needed for kernel unwinding (rare)

OBJS := $(subst $(TARGET_ARCH)/asm-offsets.o,,$(OBJS))

# remove following line if not privifying in memory
# OBJS += privify.o

default: $(OBJS) head.o xen.lds.s
	$(LD) -r -o arch.o $(OBJS)
	$(LD) $(LDFLAGS) -T $(BASEDIR)/arch/$(TARGET_ARCH)/xen.lds.s -N \
		-Map map.out head.o $(ALL_OBJS) -o $(TARGET)-syms
	$(OBJCOPY) -R .note -R .comment -S $(TARGET)-syms $(TARGET)
	$(NM) -n $(TARGET)-syms | grep -v '\( [aUw] \)\|\(__crc_\)\|\( \$[adt]\)'\
		 > $(BASEDIR)/System.map


asm-offsets.s: asm-offsets.c $(BASEDIR)/include/asm-ia64/.offsets.h.stamp $(BASEDIR)/include/asm-ia64/asm-xsi-offsets.h
	$(CC) $(CFLAGS) -S -o $@ $<

asm-xsi-offsets.s: asm-xsi-offsets.c 
	$(CC) $(CFLAGS) -S -o $@ $<

$(BASEDIR)/include/asm-ia64/asm-xsi-offsets.h: asm-xsi-offsets.s
	@(set -e; \
	  echo "/*"; \
	  echo " * DO NOT MODIFY."; \
	  echo " *"; \
	  echo " * This file was auto-generated from $<"; \
	  echo " *"; \
	  echo " */"; \
	  echo ""; \
	  echo "#ifndef __ASM_XSI_OFFSETS_H__"; \
	  echo "#define __ASM_XSI_OFFSETS_H__"; \
	  echo ""; \
	  sed -ne "/^->/{s:^->\([^ ]*\) [\$$#]*\([^ ]*\) \(.*\):#define \1 \2 /* \3 */:; s:->::; p;}"; \
	  echo ""; \
	  echo "#endif") <$< >$@

$(BASEDIR)/include/asm-ia64/.offsets.h.stamp:
# Need such symbol link to make linux headers available
	[ -e $(BASEDIR)/include/linux ] \
	 || ln -s $(BASEDIR)/include/xen $(BASEDIR)/include/linux
	[ -e $(BASEDIR)/include/asm-ia64/xen ] \
	 || ln -s $(BASEDIR)/include/asm-ia64/linux $(BASEDIR)/include/asm-ia64/xen
# Link to DM file in Xen for ia64/vti
	[ -e $(BASEDIR)/include/asm-ia64/vmx_vioapic.h ] \
	 || ln -s ../../include/asm-x86/vmx_vioapic.h $(BASEDIR)/include/asm-ia64/vmx_vioapic.h
	[ -e $(BASEDIR)/arch/ia64/vmx/vmx_vioapic.c ] \
	 || ln -s ../../../arch/x86/dm/vmx_vioapic.c $(BASEDIR)/arch/ia64/vmx/vmx_vioapic.c
# Solve circular reference on asm-offsets.h
	[ -f $(BASEDIR)/include/asm-ia64/asm-offsets.h ] \
	 || echo "#define IA64_TASK_SIZE 0" > $(BASEDIR)/include/asm-ia64/asm-offsets.h
#Bad hack. Force asm-offsets.h out-of-date
	 sleep 1
	 touch $@

# I'm sure a Makefile wizard would know a better way to do this
xen.lds.s: xen/xen.lds.S
	$(CC) -E $(CPPFLAGS) -P -DXEN -D__ASSEMBLY__ \
		-o xen.lds.s xen/xen.lds.S

# variants of divide/modulo
# see files in xen/arch/ia64/linux/lib (linux/arch/ia64/lib)
__divdi3.o: idiv64.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -o $@ $<
__udivdi3.o: idiv64.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -DUNSIGNED -c -o $@ $<
__moddi3.o: idiv64.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -DMODULO -c -o $@ $<
__umoddi3.o: idiv64.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -DMODULO -DUNSIGNED -c -o $@ $<
__divsi3.o: idiv32.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -o $@ $<
__udivsi3.o: idiv32.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -DUNSIGNED -c -o $@ $<
__modsi3.o: idiv32.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -DMODULO -c -o $@ $<
__umodsi3.o: idiv32.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -DMODULO -DUNSIGNED -c -o $@ $<


clean:
	rm -f *.o *~ core  xen.lds.s $(BASEDIR)/include/asm-ia64/.offsets.h.stamp asm-offsets.s map.out
	rm -f asm-xsi-offsets.s $(BASEDIR)/include/asm-ia64/asm-xsi-offsets.h
	rm -f linux/lib/*.o

.PHONY: default clean
