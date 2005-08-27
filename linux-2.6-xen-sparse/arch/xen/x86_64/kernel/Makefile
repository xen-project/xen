#
# Makefile for the linux kernel.
#
XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

CFLAGS	+= -Iarch/$(XENARCH)/kernel

extra-y 	:= head.o head64.o init_task.o

obj-y	:= process.o signal.o entry.o traps.o  \
		ioport.o ldt.o setup.o \
		x8664_ksyms.o vsyscall.o \
		setup64.o e820.o irq.o early_printk.o
c-obj-y	:= semaphore.o i387.o sys_x86_64.o \
		ptrace.o quirks.o syscall.o bootflag.o

i386-obj-y			:= time.o
#obj-y				+= ../../i386/kernel/timers/

s-obj-y	:=

#obj-$(CONFIG_X86_MCE)         += mce.o
#obj-$(CONFIG_MTRR)		+= ../../i386/kernel/cpu/mtrr/
obj-$(CONFIG_ACPI_BOOT)		+= acpi/
c-obj-$(CONFIG_X86_MSR)		+= msr.o
obj-$(CONFIG_MICROCODE)		+= microcode.o
obj-$(CONFIG_X86_CPUID)		+= cpuid.o
obj-$(CONFIG_SMP)		+= smp.o smpboot.o
obj-$(CONFIG_X86_LOCAL_APIC)	+= apic.o
c-obj-$(CONFIG_X86_LOCAL_APIC)	+= nmi.o
obj-$(CONFIG_X86_IO_APIC)	+= io_apic.o mpparse.o
obj-$(CONFIG_X86_XEN_GENAPIC)	+= genapic.o genapic_xen.o
c-obj-$(CONFIG_X86_IO_APIC)	+= genapic_cluster.o genapic_flat.o
#obj-$(CONFIG_PM)		+= suspend.o
#obj-$(CONFIG_SOFTWARE_SUSPEND)	+= suspend_asm.o
#obj-$(CONFIG_CPU_FREQ)		+= cpufreq/
#obj-$(CONFIG_EARLY_PRINTK)	+= early_printk.o
#obj-$(CONFIG_GART_IOMMU)	+= pci-gart.o aperture.o
obj-$(CONFIG_DUMMY_IOMMU)	+= pci-nommu.o
i386-obj-$(CONFIG_DUMMY_IOMMU)	+= pci-dma.o
i386-obj-$(CONFIG_SWIOTLB)	+= swiotlb.o
obj-$(CONFIG_KPROBES)		+= kprobes.o
#obj-$(CONFIG_X86_PM_TIMER)	+= pmtimer.o

c-obj-$(CONFIG_MODULES)		+= module.o

obj-y				+= topology.o
c-obj-y				+= intel_cacheinfo.o

bootflag-y			+= ../../../i386/kernel/bootflag.o
cpuid-$(subst m,y,$(CONFIG_X86_CPUID))  += ../../../i386/kernel/cpuid.o
topology-y                     += ../../../i386/mach-default/topology.o
#swiotlb-$(CONFIG_SWIOTLB)      += ../../../ia64/lib/swiotlb.o
microcode-$(subst m,y,$(CONFIG_MICROCODE))  += ../../../i386/kernel/microcode.o
intel_cacheinfo-y		+= ../../../i386/kernel/cpu/intel_cacheinfo.o
quirks-y			+= ../../i386/kernel/quirks.o

c-link	:= init_task.o
s-link	:= vsyscall.o 

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-obj-m) $(c-link)) $(patsubst %.o,$(obj)/%.S,$(s-obj-y) $(s-link)):
	@ln -fsn $(srctree)/arch/x86_64/kernel/$(notdir $@) $@

$(patsubst %.o,$(obj)/%.c,$(i386-obj-y)):
	@ln -fsn $(srctree)/arch/xen/i386/kernel/$(notdir $@) $@

obj-y	+= $(c-obj-y) $(s-obj-y) $(i386-obj-y)
obj-m	+= $(c-obj-m)

clean-files += $(patsubst %.o,%.c,$(c-obj-y) $(c-obj-m) $(c-obj-) $(c-link) $(i386-obj-y))
clean-files += $(patsubst %.o,%.S,$(s-obj-y) $(s-obj-) $(s-link))
