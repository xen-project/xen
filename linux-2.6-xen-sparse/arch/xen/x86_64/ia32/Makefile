#
# Makefile for the ia32 kernel emulation subsystem.
#
XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

CFLAGS	+= -Iarch/$(XENARCH)/kernel

obj-$(CONFIG_IA32_EMULATION) := ia32entry.o syscall32.o

c-obj-$(CONFIG_IA32_EMULATION) := sys_ia32.o ia32_ioctl.o \
	ia32_signal.o tls32.o \
	ia32_binfmt.o fpu32.o ptrace32.o 

s-obj-y :=

sysv-$(CONFIG_SYSVIPC) := ipc32.o
c-obj-$(CONFIG_IA32_EMULATION) += $(sysv-y)

c-obj-$(CONFIG_IA32_AOUT) += ia32_aout.o

$(obj)/syscall32.o: $(src)/syscall32.c \
	$(foreach F,int80 sysenter syscall,$(obj)/vsyscall-$F.so)

# Teach kbuild about targets
targets := $(foreach F,int80 sysenter syscall,vsyscall-$F.o vsyscall-$F.so)

# The DSO images are built using a special linker script
quiet_cmd_syscall = SYSCALL $@
      cmd_syscall = $(CC) -m32 -nostdlib -shared -s \
			   -Wl,-soname=linux-gate.so.1 -o $@ \
			   -Wl,-T,$(filter-out FORCE,$^)


$(obj)/vsyscall-int80.so $(obj)/vsyscall-sysenter.so $(obj)/vsyscall-syscall.so: \
$(obj)/vsyscall-%.so: $(obj)/vsyscall.lds $(obj)/vsyscall-%.o FORCE
	$(call if_changed,syscall)

AFLAGS_vsyscall-int80.o = -m32 -I$(obj)
AFLAGS_vsyscall-sysenter.o = -m32 -I$(obj)
AFLAGS_vsyscall-syscall.o = -m32 -I$(obj)
CFLAGS_ia32_ioctl.o += -Ifs/

s-link	:= vsyscall-syscall.o vsyscall-sysenter.o vsyscall-sigreturn.o

$(obj)/vsyscall.lds:
	@ln -fsn $(srctree)/arch/x86_64/ia32/$(notdir $@) $@

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-link)) $(patsubst %.o,$(obj)/%.S,$(s-obj-y) $(s-link)):
	@ln -fsn $(srctree)/arch/x86_64/ia32/$(notdir $@) $@

$(obj)/vsyscall-int80.o $(obj)/vsyscall-sysenter.o $(obj)/vsyscall-syscall.o: \
	$(obj)/vsyscall-sigreturn.S $(obj)/../../i386/kernel/vsyscall-note.S

$(obj)/../../i386/kernel/vsyscall-note.S:
	@ln -fsn $(srctree)/arch/i386/kernel/$(notdir $@) $@

obj-y	+= $(c-obj-y) $(s-obj-y)

clean-files += $(patsubst %.o,%.c,$(c-obj-y) $(c-obj-) $(c-link))
clean-files += $(patsubst %.o,%.S,$(s-obj-y) $(s-obj-) $(s-link))
