#include <xen/config.h>
#include <public/xen.h>
#include <asm/page.h>

#define  SECONDARY_CPU_FLAG 0xA5A5A5A5
                
       	.text

ENTRY(start)
        jmp __start

        .align	4

/*** MULTIBOOT HEADER ****/
        /* Magic number indicating a Multiboot header. */
	.long	0x1BADB002
	/* Flags to bootloader (see Multiboot spec). */
	.long	0x00000002
	/* Checksum: must be the negated sum of the first two fields. */
	.long	-0x1BADB004
        
bad_cpu_msg:
        .asciz "ERR: Not a P6-compatible CPU!"
not_multiboot_msg:
        .asciz "ERR: Not a Multiboot bootloader!"
bad_cpu:
        mov     $SYMBOL_NAME(bad_cpu_msg)-__PAGE_OFFSET,%esi
        jmp     print_err
not_multiboot:
        mov     $SYMBOL_NAME(not_multiboot_msg)-__PAGE_OFFSET,%esi
print_err:
        mov     $0xB8000,%edi  # VGA framebuffer
1:      mov     (%esi),%bl
        test    %bl,%bl        # Terminate on '\0' sentinel
2:      je      2b
        mov     $0x3f8+5,%dx   # UART Line Status Register
3:      in      %dx,%al
        test    $0x20,%al      # Test THR Empty flag
        je      3b
        mov     $0x3f8+0,%dx   # UART Transmit Holding Register
        mov     %bl,%al
        out     %al,%dx        # Send a character over the serial line
        movsb                  # Write a character to the VGA framebuffer
        mov     $7,%al
        stosb                  # Write an attribute to the VGA framebuffer
        jmp     1b
        
__start:
        /* Set up a few descriptors: on entry only CS is guaranteed good. */
        lgdt    %cs:nopaging_gdt_descr-__PAGE_OFFSET
        mov     $(__HYPERVISOR_DS),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%fs
        mov     %ecx,%gs
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

        /* Set up FPU. */
        fninit
        
        /* Set up CR4, except global flag which Intel requires should be     */
        /* left until after paging is enabled (IA32 Manual Vol. 3, Sec. 2.5) */
        mov     mmu_cr4_features-__PAGE_OFFSET,%ecx
        and     $0x7f,%cl   # CR4.PGE (global enable)
        mov     %ecx,%cr4
                
        cmp     $(SECONDARY_CPU_FLAG),%ebx
        je      start_paging
                
        /* Check for Multiboot bootloader */
        cmp     $0x2BADB002,%eax
        jne     not_multiboot

        /* Save the Multiboot info structure for later use. */
	add     $__PAGE_OFFSET,%ebx
        push    %ebx

        /* Initialize BSS (no nasty surprises!) */
        mov     $__bss_start-__PAGE_OFFSET,%edi
        mov     $_end-__PAGE_OFFSET,%ecx
        sub     %edi,%ecx
        xor     %eax,%eax
        rep     stosb

        /* Initialize low and high mappings of all memory with 4MB pages */
        mov     $idle_pg_table-__PAGE_OFFSET,%edi
        mov     $0xe3,%eax                  /* PRESENT+RW+A+D+4MB */
1:      mov     %eax,__PAGE_OFFSET>>20(%edi) /* high mapping */
        stosl                                /* low mapping */
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        cmp     $DIRECTMAP_PHYS_END+0xe3,%eax
        jne     1b
1:      stosl   /* low mappings cover as much physmem as possible */
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        cmp     $__HYPERVISOR_VIRT_START+0xe3,%eax
        jne     1b
        
        /* Initialise IDT with simple error defaults. */
        lea     ignore_int,%edx
        mov     $(__HYPERVISOR_CS << 16),%eax
        mov     %dx,%ax            /* selector = 0x0010 = cs */
        mov     $0x8E00,%dx        /* interrupt gate - dpl=0, present */
        lea     SYMBOL_NAME(idt_table)-__PAGE_OFFSET,%edi
        mov     $256,%ecx
1:      mov     %eax,(%edi)
        mov     %edx,4(%edi)
        add     $8,%edi
        loop    1b

start_paging:
        mov     $idle_pg_table-__PAGE_OFFSET,%eax
        mov     %eax,%cr3
        mov     $0x80050033,%eax /* hi-to-lo: PG,AM,WP,NE,ET,MP,PE */
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
        mov     mmu_cr4_features,%ecx
        mov     %ecx,%cr4
        /* Relocate ESP */
        add     $__PAGE_OFFSET,%esp

        lidt    idt_descr
                
        cmp     $(SECONDARY_CPU_FLAG),%ebx
        je      start_secondary

        /* Call into main C routine. This should never return.*/
       	call	__start_xen
        ud2     /* Force a panic (invalid opcode). */

/* This is the default interrupt handler. */
int_msg:
        .asciz "Unknown interrupt\n"
        ALIGN
ignore_int:
        cld
        mov     $(__HYPERVISOR_DS),%eax
        mov     %eax,%ds
        mov     %eax,%es
        pushl   $int_msg
        call    SYMBOL_NAME(printf)
1:      jmp     1b

/*** STACK LOCATION ***/
        
ENTRY(stack_start)
        .long SYMBOL_NAME(cpu0_stack) + STACK_SIZE - 200 - __PAGE_OFFSET
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
	.word	(LAST_RESERVED_GDT_ENTRY*8)+7
SYMBOL_NAME(gdt):       
        .long   SYMBOL_NAME(gdt_table)	/* gdt base */

        .word   0
nopaging_gdt_descr:
        .word   (LAST_RESERVED_GDT_ENTRY*8)+7
        .long   SYMBOL_NAME(gdt_table)-__PAGE_OFFSET
        
        ALIGN
/* NB. Rings != 0 get access up to 0xFC400000. This allows access to the */
/*     machine->physical mapping table. Ring 0 can access all memory.    */
ENTRY(gdt_table)
        .fill FIRST_RESERVED_GDT_ENTRY,8,0
        .quad 0x0000000000000000     /* unused */
        .quad 0x00cf9a000000ffff     /* 0x0808 ring 0 4.00GB code at 0x0 */
        .quad 0x00cf92000000ffff     /* 0x0810 ring 0 4.00GB data at 0x0 */
        .quad 0x00cfba000000c3ff     /* 0x0819 ring 1 3.95GB code at 0x0 */
        .quad 0x00cfb2000000c3ff     /* 0x0821 ring 1 3.95GB data at 0x0 */
        .quad 0x00cffa000000c3ff     /* 0x082b ring 3 3.95GB code at 0x0 */
        .quad 0x00cff2000000c3ff     /* 0x0833 ring 3 3.95GB data at 0x0 */
        .quad 0x0000000000000000     /* unused                           */
        .fill 2*NR_CPUS,8,0          /* space for TSS and LDT per CPU    */

        .org 0x1000
ENTRY(idle_pg_table) # Initial page directory is 4kB
        .org 0x2000
ENTRY(cpu0_stack)    # Initial stack is 8kB
        .org 0x4000
ENTRY(stext)
ENTRY(_stext)
