
.section __xen_guest
    .ascii "GUEST_OS=linux,GUEST_VER=2.4,XEN_VER=3.0,VIRT_BASE=0xC0000000"
    .ascii ",LOADER=generic"
    .ascii ",PT_MODE_WRITABLE"
    .byte  0

.text
#include <linux/config.h>
#include <linux/threads.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/desc.h>

ENTRY(stext)
ENTRY(_stext)
        cld
        lss stack_start,%esp
        /* Copy the necessary stuff from xen_start_info structure. */
        mov $SYMBOL_NAME(xen_start_info_union),%edi
        mov $128,%ecx
        rep movsl
        jmp SYMBOL_NAME(start_kernel)

ENTRY(stack_start)
	.long SYMBOL_NAME(init_task_union)+8192, __KERNEL_DS

.org 0x1000
ENTRY(empty_zero_page)

.org 0x2000
ENTRY(default_ldt)

.org 0x3000
ENTRY(cpu0_pte_quicklist)

.org 0x3400
ENTRY(cpu0_pgd_quicklist)
        
.org 0x3800
