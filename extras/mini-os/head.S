#include <os.h>

/* Offsets in start_info structure */
#define MOD_START    4
#define MOD_LEN      8

.globl _start, shared_info
                        
_start:
        cld
        
        lss stack_start,%esp
        
        /* Copy any module somewhere safe before it's clobbered by BSS. */
        mov  MOD_LEN(%esi),%ecx
        shr  $2,%ecx
        jz   2f        /* bail from copy loop if no module */
        
        mov  $_end,%edi
        add  MOD_LEN(%esi),%edi
        mov  MOD_START(%esi),%eax
        add  MOD_LEN(%esi),%eax
1:      sub  $4,%eax
        sub  $4,%edi
        mov  (%eax),%ebx
        mov  %ebx,(%edi)
        loop 1b
        mov  %edi,MOD_START(%esi)

        /* Clear BSS first so that there are no surprises... */
2:      xorl %eax,%eax
        movl $__bss_start,%edi
        movl $_end,%ecx
        subl %edi,%ecx
        rep stosb

        push %esi 
        call start_kernel


stack_start:
	.long stack+8192, __KERNEL_DS


        /* Unpleasant -- we actually use this PTE to map shared_info :-) */
        .org 0x1000
shared_info:
        .org 0x2000
