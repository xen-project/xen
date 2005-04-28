.global call_with_registers

#include <asm/asm-offsets.h>

	// int call_with_registers(void (*f)(struct cpu_user_regs *r)) ->
	// build a cpu_user_regs structure, and then call f with that.
call_with_registers:
	pushf
	subl $UREGS_user_sizeof, %esp
	movl %ebx, UREGS_ebx(%esp)
	movl %ecx, UREGS_ecx(%esp)
	movl %edx, UREGS_edx(%esp)
	movl %esi, UREGS_esi(%esp)
	movl %edi, UREGS_edi(%esp)
	movl %ebp, UREGS_ebp(%esp)
	movl %eax, UREGS_eax(%esp)
	movw $0, UREGS_error_code(%esp)
	movw $0, UREGS_entry_vector(%esp)
	movl UREGS_user_sizeof+4(%esp), %eax
	movl %eax, UREGS_eip(%esp)
	movl %cs, UREGS_cs(%esp)
	movl UREGS_user_sizeof(%esp), %eax
	movl %eax, UREGS_eflags(%esp)
	movl %esp, UREGS_esp(%esp)
	addl $UREGS_user_sizeof+4, UREGS_esp(%esp)
	movl %ss, UREGS_ss(%esp)
	movl %es, UREGS_es(%esp)
	movl %ds, UREGS_ds(%esp)
	movl %fs, UREGS_fs(%esp)
	movl %gs, UREGS_gs(%esp)

	movl UREGS_user_sizeof+8(%esp), %eax
	pushl %esp
	call *%eax
	add $UREGS_user_sizeof + 8, %esp
	ret
