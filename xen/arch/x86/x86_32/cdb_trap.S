.global cdb_trap
.extern __trap_to_cdb
	
#define SAVE_ALL_NOSEGREGS \
	pushw $0;  \
        pushw %gs; \
	pushw $0;  \
        pushw %fs; \
	pushw $0;  \
        pushw %es; \
	pushw $0;  \
        pushw %ds; \
        pushl %eax; \
        pushl %ebp; \
        pushl %edi; \
        pushl %esi; \
        pushl %edx; \
        pushl %ecx; \
        pushl %ebx;

	// Save the register state and call __trap_to_cdb
cdb_trap:
	pushw $0
	pushw %ss
	pushl %esp //We'll fix this up later, in __trap_to_cdb, by adding 8
	pushf
	pushw $0
	pushw %cs
	pushl 16(%esp)
1:	pushl $0 		// Orig_eax
	SAVE_ALL_NOSEGREGS
	pushl %esp
	call __trap_to_cdb
	add $72, %esp
	xorl %eax, %eax
	ret
