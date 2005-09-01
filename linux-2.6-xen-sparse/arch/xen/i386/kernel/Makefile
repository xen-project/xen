#
# Makefile for the linux kernel.
#

XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

CFLAGS	+= -Iarch/$(XENARCH)/kernel
AFLAGS	+= -Iarch/$(XENARCH)/kernel

extra-y := head.o init_task.o

obj-y	:= process.o signal.o entry.o traps.o \
		time.o ioport.o ldt.o setup.o \
		pci-dma.o i386_ksyms.o irq.o quirks.o

c-obj-y	:= semaphore.o vm86.o \
		ptrace.o sys_i386.o \
		i387.o dmi_scan.o bootflag.o
s-obj-y	:=

obj-y				+= cpu/
#obj-y				+= timers/
obj-$(CONFIG_ACPI_BOOT)		+= acpi/
#c-obj-$(CONFIG_X86_BIOS_REBOOT)	+= reboot.o
c-obj-$(CONFIG_MCA)		+= mca.o
c-obj-$(CONFIG_X86_MSR)		+= msr.o
c-obj-$(CONFIG_X86_CPUID)	+= cpuid.o
obj-$(CONFIG_MICROCODE)		+= microcode.o
c-obj-$(CONFIG_APM)		+= apm.o
obj-$(CONFIG_X86_SMP)		+= smp.o smpboot.o
#obj-$(CONFIG_X86_TRAMPOLINE)	+= trampoline.o
obj-$(CONFIG_X86_MPPARSE)	+= mpparse.o
obj-$(CONFIG_X86_LOCAL_APIC)	+= apic.o
c-obj-$(CONFIG_X86_LOCAL_APIC)	+= nmi.o
obj-$(CONFIG_X86_IO_APIC)	+= io_apic.o
c-obj-$(CONFIG_X86_REBOOTFIXUPS)	+= reboot_fixups.o
c-obj-$(CONFIG_X86_NUMAQ)	+= numaq.o
c-obj-$(CONFIG_X86_SUMMIT_NUMA)	+= summit.o
c-obj-$(CONFIG_MODULES)		+= module.o
c-obj-y				+= sysenter.o
obj-y				+= vsyscall.o
c-obj-$(CONFIG_ACPI_SRAT) 	+= srat.o
c-obj-$(CONFIG_HPET_TIMER) 	+= time_hpet.o
c-obj-$(CONFIG_EFI) 		+= efi.o efi_stub.o
c-obj-$(CONFIG_EARLY_PRINTK)	+= early_printk.o
c-obj-$(CONFIG_SMP_ALTERNATIVES)+= smpalts.o
obj-$(CONFIG_SWIOTLB)		+= swiotlb.o

EXTRA_AFLAGS   := -traditional

c-obj-$(CONFIG_SCx200)		+= scx200.o

# vsyscall.o contains the vsyscall DSO images as __initdata.
# We must build both images before we can assemble it.
# Note: kbuild does not track this dependency due to usage of .incbin
$(obj)/vsyscall.o: $(obj)/vsyscall-int80.so $(obj)/vsyscall-sysenter.so
targets += $(foreach F,int80 sysenter,vsyscall-$F.o vsyscall-$F.so)
targets += vsyscall-note.o vsyscall.lds

# The DSO images are built using a special linker script.
quiet_cmd_syscall = SYSCALL $@
      cmd_syscall = $(CC) -m elf_i386 -nostdlib $(SYSCFLAGS_$(@F)) \
		          -Wl,-T,$(filter-out FORCE,$^) -o $@

export CPPFLAGS_vsyscall.lds += -P -C -U$(ARCH)

vsyscall-flags = -shared -s -Wl,-soname=linux-gate.so.1
SYSCFLAGS_vsyscall-sysenter.so	= $(vsyscall-flags)
SYSCFLAGS_vsyscall-int80.so	= $(vsyscall-flags)

$(obj)/vsyscall-int80.so $(obj)/vsyscall-sysenter.so: \
$(obj)/vsyscall-%.so: $(src)/vsyscall.lds \
		      $(obj)/vsyscall-%.o $(obj)/vsyscall-note.o FORCE
	$(call if_changed,syscall)

# We also create a special relocatable object that should mirror the symbol
# table and layout of the linked DSO.  With ld -R we can then refer to
# these symbols in the kernel code rather than hand-coded addresses.
extra-y += vsyscall-syms.o
$(obj)/built-in.o: $(obj)/vsyscall-syms.o
$(obj)/built-in.o: ld_flags += -R $(obj)/vsyscall-syms.o

SYSCFLAGS_vsyscall-syms.o = -r
$(obj)/vsyscall-syms.o: $(src)/vsyscall.lds \
			$(obj)/vsyscall-sysenter.o $(obj)/vsyscall-note.o FORCE
	$(call if_changed,syscall)

c-link	:=
s-link	:= vsyscall-int80.o vsyscall-sysenter.o vsyscall-sigreturn.o vsyscall.lds.o vsyscall-note.o

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-obj-m) $(c-link)) $(patsubst %.o,$(obj)/%.S,$(s-obj-y) $(s-link)):
	@ln -fsn $(srctree)/arch/i386/kernel/$(notdir $@) $@

$(obj)/vsyscall-int80.S: $(obj)/vsyscall-sigreturn.S

obj-y	+= $(c-obj-y) $(s-obj-y)
obj-m	+= $(c-obj-m)

clean-files += $(patsubst %.o,%.c,$(c-obj-y) $(c-obj-m) $(c-obj-) $(c-link))
clean-files += $(patsubst %.o,%.S,$(s-obj-y) $(s-obj-) $(s-link))
