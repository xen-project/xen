#include <os.h>

.globl _start, shared_info
                        
_start:
        cld
        lss stack_start,%esp
        push %esi 
        call start_kernel

stack_start:
	.long stack+8192, __KERNEL_DS

        /* Unpleasant -- the PTE that maps this page is actually overwritten */
        /* to map the real shared-info page! :-)                             */
        .org 0x1000
shared_info:
        .org 0x2000
