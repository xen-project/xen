#include <xeno/config.h>
#include <asm/page.h>

#define  SECONDARY_CPU_FLAG 0xA5A5A5A5
                
       	.text

ENTRY(start)
        jmp hal_entry

        .align	4

/*** MULTIBOOT HEADER ****/
        /* Magic number indicating a Multiboot header. */
	.long	0x1BADB002
	/* Flags to bootloader (see Multiboot spec). */
	.long	0x00000006
	/* Checksum: must be the negated sum of the first two fields. */
	.long	-0x1BADB008
        /* Unused loader addresses (ELF header has all this already).*/
        .long   0,0,0,0,0
        /* EGA text mode. */
        .long   1,0,0,0
        
hal_entry:
        /* Set up a few descriptors: on entry only CS is guaranteed good. */
        lgdt    %cs:nopaging_gdt_descr-__PAGE_OFFSET
        mov     $(__HYPERVISOR_DS),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        ljmp    $(__HYPERVISOR_CS),$(1f)-__PAGE_OFFSET
1:      lss     stack_start-__PAGE_OFFSET,%esp

        /* Reset EFLAGS (subsumes CLI and CLD). */
	pushl	$0
	popf

        /* CPU type checks. We need P6+. */
        mov     $0x200000,%edx
        pushfl
        pop     %ecx
        and     %edx,%ecx
        jne     bad_cpu            # ID bit should be clear
        pushl   %edx
        popfl
        pushfl
        pop     %ecx
        and     %edx,%ecx
        je      bad_cpu            # ID bit should be set

        /* Set up CR0. */
        mov     %cr0,%ecx
        and     $0x00000011,%ecx   # save ET and PE
        or      $0x00050022,%ecx   # set AM, WP, NE and MP
        mov     %ecx,%cr0

        /* Set up FPU. */
        fninit
        
        /* Set up CR4, except global flag which Intel requires should be     */
        /* left until after paging is enabled (IA32 Manual Vol. 3, Sec. 2.5) */
        mov     %cr4,%ecx
        or      mmu_cr4_features-__PAGE_OFFSET,%ecx
        mov     %ecx,mmu_cr4_features-__PAGE_OFFSET
        and     $0x7f,%ecx /* disable GLOBAL bit */
        mov     %ecx,%cr4
                
#ifdef CONFIG_SMP
        /* Is this a non-boot processor? */
        cmp     $(SECONDARY_CPU_FLAG),%ebx
        jne     continue_boot_cpu
        
        call    start_paging
        lidt    idt_descr                        
        jmp     initialize_secondary
#endif
        
continue_boot_cpu:
	add     $__PAGE_OFFSET,%ebx
        push    %ebx /* Multiboot info struct */
        push    %eax /* Multiboot magic value */

        /* Initialize BSS (no nasty surprises!) */
        mov     $__bss_start-__PAGE_OFFSET,%edi
        mov     $_end-__PAGE_OFFSET,%ecx
        sub     %edi,%ecx
        xor     %eax,%eax
        rep     stosb

        /* Copy all modules (dom0 + initrd if present) out of the Xen heap */
        mov     (%esp),%eax
        cmp     $0x2BADB002,%eax
        jne     skip_dom0_copy
        sub     $__PAGE_OFFSET,%ebx          /* turn back into a phys addr */
        mov     0x14(%ebx),%edi              /* mb->mods_count */
        dec     %edi                         /* mbi->mods_count-- */
        jb      skip_dom0_copy               /* skip if no modules */
        mov     0x18(%ebx),%eax              /* mbi->mods_addr */
        mov     (%eax),%ebx                  /* %ebx = mod[0]->mod_start */
        shl     $4,%edi                    
        add     %edi,%eax
        mov     0x4(%eax),%eax               /* %eax = mod[mod_count-1]->end */
        mov     %eax,%ecx
        sub     %ebx,%ecx                    /* %ecx = byte len of all mods */
        mov     $(MAX_DIRECTMAP_ADDRESS), %edi
        add     %ecx, %edi                   /* %edi = src + length */        
        shr     $2,%ecx                      /* %ecx = length/4 */
1:      sub     $4,%eax                      /* %eax = src, %edi = dst */
        sub     $4,%edi
        mov     (%eax),%ebx
        mov     %ebx,(%edi)
        loop 1b
skip_dom0_copy:              

        /* Initialize low and high mappings of all memory with 4MB pages */
        mov     $idle0_pg_table-__PAGE_OFFSET,%edi
        mov     $0x1e3,%eax                  /* PRESENT+RW+A+D+4MB+GLOBAL */
1:      mov     %eax,__PAGE_OFFSET>>20(%edi) /* high mapping */
        stosl                                /* low mapping */
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        cmp     $MAX_DIRECTMAP_ADDRESS+0x1e3,%eax
        jne     1b

        call    start_paging        
        call    setup_idt
        lidt    idt_descr
                
        /* Call into main C routine. This should never return.*/
       	call	cmain
        ud2     /* Force a panic (invalid opcode). */

start_paging:
        mov     $idle0_pg_table-__PAGE_OFFSET,%eax
        mov     %eax,%cr3
        mov     %cr0,%eax
        or      $0x80010000,%eax /* set PG and WP bits */
        mov     %eax,%cr0
        jmp     1f
1:      /* Install relocated selectors (FS/GS unused). */
        lgdt    gdt_descr
        mov     $(__HYPERVISOR_DS),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%ss
        ljmp    $(__HYPERVISOR_CS),$1f
1:      /* Paging enabled, so we can now enable GLOBAL mappings in CR4. */
        movl    mmu_cr4_features,%ecx
        movl    %ecx,%cr4
        /* Relocate ESP */
        add     $__PAGE_OFFSET,%esp
        /* Relocate EIP via return jump */
        pop     %ecx
        add     $__PAGE_OFFSET,%ecx
        jmp     *%ecx
    
            
/*** INTERRUPT INITIALISATION ***/
        
setup_idt:
        lea     ignore_int,%edx
        mov     $(__HYPERVISOR_CS << 16),%eax
        mov     %dx,%ax            /* selector = 0x0010 = cs */
        mov     $0x8E00,%dx        /* interrupt gate - dpl=0, present */

        lea     SYMBOL_NAME(idt_table),%edi
        mov     $256,%ecx
1:      mov     %eax,(%edi)
        mov     %edx,4(%edi)
        add     $8,%edi
        loop    1b
        ret

/* This is the default interrupt handler. */
int_msg:
        .asciz "Unknown interrupt\n"
        ALIGN
ignore_int:
        cld
        push    %eax
        push    %ecx
        push    %edx
        pushl   %es
        pushl   %ds
        mov     $(__HYPERVISOR_DS),%eax
        mov     %eax,%ds
        mov     %eax,%es
        pushl   $int_msg
        call    SYMBOL_NAME(printf)
1:      jmp     1b
        pop     %eax
        popl    %ds
        popl    %es
        pop     %edx
        pop     %ecx
        pop     %eax
        iret


bad_cpu_msg:
        .asciz  "Bad CPU type. Need P6+."
        ALIGN
bad_cpu:
/* NB. We assume the UART is set up correctly. */
        mov     $bad_cpu_msg,%esi
1:      lodsb
        test    %al,%al
        je      1f
        push    %eax
        call    putchar_serial
        add     $4,%esp
        jmp     1b
1:      jmp     1b
                   
        
/*** STACK LOCATION ***/
        
ENTRY(stack_start)
        .long SYMBOL_NAME(idle0_task_union)+8192-__PAGE_OFFSET
        .long __HYPERVISOR_DS
        
/*** DESCRIPTOR TABLES ***/

.globl SYMBOL_NAME(idt)
.globl SYMBOL_NAME(gdt)        

        ALIGN
        
        .word   0    
idt_descr:
	.word	256*8-1
SYMBOL_NAME(idt):
        .long	SYMBOL_NAME(idt_table)

        .word   0
gdt_descr:
	.word	(2*NR_CPUS+8)*8-1
SYMBOL_NAME(gdt):       
        .long   SYMBOL_NAME(gdt_table)	/* gdt base */

        .word   0
nopaging_gdt_descr:
        .word   (2*NR_CPUS+8)*8-1
        .long   SYMBOL_NAME(gdt_table)-__PAGE_OFFSET
        
        ALIGN
/* NB. Rings != 0 get access up to 0xFC400000. This allows access to the */
/*     machine->physical mapping table. Ring 0 can access all memory.    */
ENTRY(gdt_table)
        .quad 0x0000000000000000     /* 0x0000 NULL descriptor */
        .quad 0x00cf9a000000ffff     /* 0x0008 ring 0 4.00GB code at 0x0 */
        .quad 0x00cf92000000ffff     /* 0x0010 ring 0 4.00GB data at 0x0 */
        .quad 0x00cfba000000c3ff     /* 0x0019 ring 1 3.95GB code at 0x0 */
        .quad 0x00cfb2000000c3ff     /* 0x0021 ring 1 3.95GB data at 0x0 */
        .quad 0x00cffa000000c3ff     /* 0x002b ring 3 3.95GB code at 0x0 */
        .quad 0x00cff2000000c3ff     /* 0x0033 ring 3 3.95GB data at 0x0 */
        .quad 0x0000000000000000     /* unused                           */
        .fill 2*NR_CPUS,8,0          /* space for TSS and LDT per CPU    */

# The following adds 12kB to the kernel file size.
        .org 0x1000
ENTRY(idle0_pg_table)
        .org 0x2000
ENTRY(idle0_task_union)
        .org 0x4000
ENTRY(stext)
ENTRY(_stext)
