        .code64

        /* Install relocated data selectors. */
        lgdt    gdt_descr(%rip)
        mov     $(__HYPERVISOR_DS64),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%fs
        mov     %ecx,%gs
        mov     %ecx,%ss

        /* Enable full CR4 features. */
        mov     mmu_cr4_features(%rip),%rcx
        mov     %rcx,%cr4

        mov     stack_start(%rip),%rsp
        or      $(STACK_SIZE-CPUINFO_sizeof),%rsp

        /* Reset EFLAGS (subsumes CLI and CLD). */
        pushq   $0
        popf

        /* Reload code selector. */
        pushq   $(__HYPERVISOR_CS64)
        leaq    1f(%rip),%rax
        pushq   %rax
        lretq
1:      lidt    idt_descr(%rip)

        test    %ebx,%ebx
        jnz     start_secondary

        /* Initialise IDT with simple error defaults. */
        leaq    ignore_int(%rip),%rcx
        movl    %ecx,%eax
        andl    $0xFFFF0000,%eax
        orl     $0x00008E00,%eax
        shlq    $32,%rax
        movl    %ecx,%edx
        andl    $0x0000FFFF,%edx
        orl     $(__HYPERVISOR_CS64<<16),%edx
        orq     %rdx,%rax
        shrq    $32,%rcx
        movl    %ecx,%edx
        leaq    idt_table(%rip),%rdi
        movl    $256,%ecx
1:      movq    %rax,(%rdi)
        movq    %rdx,8(%rdi)
        addq    $16,%rdi
        loop    1b

        /* Pass off the Multiboot info structure to C land. */
        mov     multiboot_ptr(%rip),%edi
        call    __start_xen
        ud2     /* Force a panic (invalid opcode). */

/* This is the default interrupt handler. */
int_msg:
        .asciz "Unknown interrupt (cr2=%016lx)\n"
hex_msg:
        .asciz "    %016lx"
ignore_int:
        SAVE_ALL
        movq    %cr2,%rsi
        leaq    int_msg(%rip),%rdi
        xorl    %eax,%eax
        call    printk
        movq    %rsp,%rbp
0:      movq    (%rbp),%rsi
        addq    $8,%rbp
        leaq    hex_msg(%rip),%rdi
        xorl    %eax,%eax
        call    printk
        testq   $0xff8,%rbp
        jnz     0b
1:      jmp     1b


/*** DESCRIPTOR TABLES ***/

        .data
        .align 8
multiboot_ptr:
        .long   0

        .word   0
        .globl  gdt_descr
gdt_descr:
        .word   LAST_RESERVED_GDT_BYTE
        .quad   boot_cpu_gdt_table - FIRST_RESERVED_GDT_BYTE

        .word   0,0,0
        .globl  idt_descr
idt_descr:
        .word   256*16-1
        .quad   idt_table

ENTRY(stack_start)
        .quad   cpu0_stack

        .section .data.page_aligned, "aw", @progbits
        .align PAGE_SIZE, 0
ENTRY(boot_cpu_gdt_table)
        .quad 0x0000000000000000     /* unused */
        .quad 0x00af9a000000ffff     /* 0xe008 ring 0 code, 64-bit mode   */
        .quad 0x00cf92000000ffff     /* 0xe010 ring 0 data                */
        .quad 0x0000000000000000     /* reserved                          */
        .quad 0x00cffa000000ffff     /* 0xe023 ring 3 code, compatibility */
        .quad 0x00cff2000000ffff     /* 0xe02b ring 3 data                */
        .quad 0x00affa000000ffff     /* 0xe033 ring 3 code, 64-bit mode   */
        .quad 0x00cf9a000000ffff     /* 0xe038 ring 0 code, compatibility */
        .fill (PER_CPU_GDT_ENTRY - __HYPERVISOR_CS32 / 8 - 1), 8, 0
        .quad 0x0000910000000000     /* per-CPU entry (limit == cpu)      */

        .align PAGE_SIZE, 0
/* NB. Even rings != 0 get access to the full 4Gb, as only the            */
/*     (compatibility) machine->physical mapping table lives there.       */
ENTRY(boot_cpu_compat_gdt_table)
        .quad 0x0000000000000000     /* unused */
        .quad 0x00af9a000000ffff     /* 0xe008 ring 0 code, 64-bit mode   */
        .quad 0x00cf92000000ffff     /* 0xe010 ring 0 data                */
        .quad 0x00cfba000000ffff     /* 0xe019 ring 1 code, compatibility */
        .quad 0x00cfb2000000ffff     /* 0xe021 ring 1 data                */
        .quad 0x00cffa000000ffff     /* 0xe02b ring 3 code, compatibility */
        .quad 0x00cff2000000ffff     /* 0xe033 ring 3 data                */
        .quad 0x00cf9a000000ffff     /* 0xe038 ring 0 code, compatibility */
        .fill (PER_CPU_GDT_ENTRY - __HYPERVISOR_CS32 / 8 - 1), 8, 0
        .quad 0x0000910000000000     /* per-CPU entry (limit == cpu)      */
        .align PAGE_SIZE, 0
