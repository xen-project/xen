
.text
#include <linux/config.h>
#include <linux/threads.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/desc.h>

/* Offsets in start_info structure */
#define MOD_START 16
#define MOD_LEN   20
                
startup_32:
        cld
        
        lss stack_start,%esp

        /* Copy initrd somewhere safe before it's clobbered by BSS. */
        mov  MOD_LEN(%esi),%ecx
        shr  $2,%ecx
        jz   2f        /* bail from copy loop if no initrd */
        mov  $SYMBOL_NAME(_end),%edi
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
        movl $SYMBOL_NAME(__bss_start),%edi
        movl $SYMBOL_NAME(_end),%ecx
        subl %edi,%ecx
        rep stosb

        /* Copy the necessary stuff from start_info structure. */
        mov  $SYMBOL_NAME(start_info_union),%edi
        mov  $128,%ecx
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
ENTRY(stext)
ENTRY(_stext)
