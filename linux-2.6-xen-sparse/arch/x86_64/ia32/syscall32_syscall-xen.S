/* 32bit VDSOs mapped into user space. */

	.section ".init.data","aw"

#ifdef USE_INT80

	.globl syscall32_int80
	.globl syscall32_int80_end

syscall32_int80:
	.incbin "arch/x86_64/ia32/vsyscall-int80.so"
syscall32_int80_end:

#endif

	.globl syscall32_syscall
	.globl syscall32_syscall_end

syscall32_syscall:
	.incbin "arch/x86_64/ia32/vsyscall-syscall.so"
syscall32_syscall_end:

	.globl syscall32_sysenter
	.globl syscall32_sysenter_end

syscall32_sysenter:
	.incbin "arch/x86_64/ia32/vsyscall-sysenter.so"
syscall32_sysenter_end:
