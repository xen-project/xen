.global call_with_registers

#include <asm/asm-offsets.h>

	// int call_with_registers(void (*f)(struct xen_regs *r)) ->
	// build a xen_regs structure, and then call f with that.
call_with_registers:
	pushf
	subl $XREGS_user_sizeof, %esp
	movl %ebx, XREGS_ebx(%esp)
	movl %ecx, XREGS_ecx(%esp)
	movl %edx, XREGS_edx(%esp)
	movl %esi, XREGS_esi(%esp)
	movl %edi, XREGS_edi(%esp)
	movl %ebp, XREGS_ebp(%esp)
	movl %eax, XREGS_eax(%esp)
	movw $0, XREGS_error_code(%esp)
	movw $0, XREGS_entry_vector(%esp)
	movl XREGS_user_sizeof+4(%esp), %eax
	movl %eax, XREGS_eip(%esp)
	movl %cs, XREGS_cs(%esp)
	movl XREGS_user_sizeof(%esp), %eax
	movl %eax, XREGS_eflags(%esp)
	movl %esp, XREGS_esp(%esp)
	addl $XREGS_user_sizeof+4, XREGS_esp(%esp)
	movl %ss, XREGS_ss(%esp)
	movl %es, XREGS_es(%esp)
	movl %ds, XREGS_ds(%esp)
	movl %fs, XREGS_fs(%esp)
	movl %gs, XREGS_gs(%esp)

	movl XREGS_user_sizeof+8(%esp), %eax
	pushl %esp
	call *%eax
	add $XREGS_user_sizeof + 8, %esp
	ret
