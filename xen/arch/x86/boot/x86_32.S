        .code32
        
        /* Enable full CR4 features. */
        mov     mmu_cr4_features,%eax
        mov     %eax,%cr4
        
        /* Initialise stack. */
        mov     stack_start,%esp
        or      $(STACK_SIZE-CPUINFO_sizeof),%esp
        
        /* Reset EFLAGS (subsumes CLI and CLD). */
        pushl   $0
        popf

        lidt    idt_descr

        test    %ebx,%ebx
        jnz     start_secondary

        /* Initialise IDT with simple error defaults. */
        lea     ignore_int,%edx
        mov     $(__HYPERVISOR_CS << 16),%eax
        mov     %dx,%ax            /* selector = 0x0010 = cs */
        mov     $0x8E00,%dx        /* interrupt gate - dpl=0, present */
        lea     idt_table,%edi
        mov     $256,%ecx
1:      mov     %eax,(%edi)
        mov     %edx,4(%edi)
        add     $8,%edi
        loop    1b
                
        /* Pass off the Multiboot info structure to C land. */
        pushl   multiboot_ptr
        call    __start_xen
        ud2     /* Force a panic (invalid opcode). */

/* This is the default interrupt handler. */
int_msg:
        .asciz "Unknown interrupt (cr2=%08x)\n"
hex_msg:
        .asciz "  %08x"
        ALIGN
ignore_int:
        pusha
        cld
        mov     $(__HYPERVISOR_DS),%eax
        mov     %eax,%ds
        mov     %eax,%es
        mov     %cr2,%eax
        push    %eax
        pushl   $int_msg
        call    printk
        add     $8,%esp
        mov     %esp,%ebp
0:      pushl   (%ebp)
        add     $4,%ebp
        pushl   $hex_msg
        call    printk
        add     $8,%esp
        test    $0xffc,%ebp
        jnz     0b
1:      jmp     1b

        .data
        ALIGN
ENTRY(stack_start)
        .long cpu0_stack
        
/*** DESCRIPTOR TABLES ***/

        ALIGN
multiboot_ptr:
        .long   0
        
        .word   0    
idt_descr:
        .word   256*8-1
        .long   idt_table

        .word   0
gdt_descr:
        .word   LAST_RESERVED_GDT_BYTE
        .long   boot_cpu_gdt_table - FIRST_RESERVED_GDT_BYTE


        .align 32
ENTRY(idle_pg_table)
        .long sym_phys(idle_pg_table_l2) + 0*PAGE_SIZE + 0x01, 0
        .long sym_phys(idle_pg_table_l2) + 1*PAGE_SIZE + 0x01, 0
        .long sym_phys(idle_pg_table_l2) + 2*PAGE_SIZE + 0x01, 0
        .long sym_phys(idle_pg_table_l2) + 3*PAGE_SIZE + 0x01, 0

        .section .data.page_aligned, "aw", @progbits
        .align PAGE_SIZE, 0
/* NB. Rings != 0 get access up to MACH2PHYS_VIRT_END. This allows access to */
/*     the machine->physical mapping table. Ring 0 can access all memory.    */
#define GUEST_DESC(d)                                                   \
        .long ((MACH2PHYS_VIRT_END - 1) >> 12) & 0xffff,                \
              ((MACH2PHYS_VIRT_END - 1) >> 12) & (0xf << 16) | (d)
ENTRY(boot_cpu_gdt_table)
        .quad 0x0000000000000000     /* double fault TSS */
        .quad 0x00cf9a000000ffff     /* 0xe008 ring 0 4.00GB code at 0x0 */
        .quad 0x00cf92000000ffff     /* 0xe010 ring 0 4.00GB data at 0x0 */
        GUEST_DESC(0x00c0ba00)       /* 0xe019 ring 1 3.xxGB code at 0x0 */
        GUEST_DESC(0x00c0b200)       /* 0xe021 ring 1 3.xxGB data at 0x0 */
        GUEST_DESC(0x00c0fa00)       /* 0xe02b ring 3 3.xxGB code at 0x0 */
        GUEST_DESC(0x00c0f200)       /* 0xe033 ring 3 3.xxGB data at 0x0 */
        .fill (PER_CPU_GDT_ENTRY - FLAT_RING3_DS / 8 - 1), 8, 0
        .quad 0x0000910000000000     /* per-CPU entry (limit == cpu) */
        .align PAGE_SIZE,0
