        .code16

        .globl trampoline_realmode_entry
trampoline_realmode_entry:
        nop                               # We use this byte as a progress flag
        movb    $0xA5,trampoline_cpu_started - trampoline_start
        cld
        cli
        lidt    %cs:idt_48 - trampoline_start
        lgdt    %cs:gdt_48 - trampoline_start
        xor     %ax, %ax
        inc     %ax
        lmsw    %ax                       # CR0.PE = 1 (enter protected mode)
        mov     $1,%bl                    # EBX != 0 indicates we are an AP
        jmp     1f
1:      ljmpl   $TRAMP_CS32,$SYM_TRAMP_PHYS(trampoline_protmode_entry)

idt_48: .word   0, 0, 0 # base = limit = 0
gdt_48: .word   4*8-1
        .long   SYM_TRAMP_PHYS(trampoline_gdt)
trampoline_gdt:
        .quad   0x0000000000000000     /* 0x0000: unused */
        .quad   0x00cf9a000000ffff     /* 0x0008: ring 0 code, 32-bit mode */
        .quad   0x00af9a000000ffff     /* 0x0010: ring 0 code, 64-bit mode */
        .quad   0x00cf92000000ffff     /* 0x0018: ring 0 data */

cpuid_ext_features:
        .long   0

        .globl trampoline_xen_phys_start
trampoline_xen_phys_start:
        .long   0

        .globl trampoline_cpu_started
trampoline_cpu_started:
        .byte   0

        .code32
trampoline_protmode_entry:
        /* Set up a few descriptors: on entry only CS is guaranteed good. */
        mov     $TRAMP_DS,%eax
        mov     %eax,%ds
        mov     %eax,%es

        /* Set up FPU. */
        fninit

        /* Initialise CR4. */
#if CONFIG_PAGING_LEVELS == 2
        mov     $X86_CR4_PSE,%ecx
#else
        mov     $X86_CR4_PAE,%ecx
#endif
        mov     %ecx,%cr4

        /* Load pagetable base register. */
        mov     $SYM_PHYS(idle_pg_table),%eax
        add     SYM_TRAMP_PHYS(trampoline_xen_phys_start),%eax
        mov     %eax,%cr3

#if CONFIG_PAGING_LEVELS != 2
        /* Set up EFER (Extended Feature Enable Register). */
        mov     SYM_TRAMP_PHYS(cpuid_ext_features),%edi
        test    $0x20100800,%edi /* SYSCALL/SYSRET, No Execute, Long Mode? */
        jz      .Lskip_efer
        movl    $MSR_EFER,%ecx
        rdmsr
#if CONFIG_PAGING_LEVELS == 4
        btsl    $_EFER_LME,%eax /* Long Mode      */
        btsl    $_EFER_SCE,%eax /* SYSCALL/SYSRET */
#endif
        btl     $20,%edi        /* No Execute?    */
        jnc     1f
        btsl    $_EFER_NX,%eax  /* No Execute     */
1:      wrmsr
.Lskip_efer:
#endif

        mov     $0x80050033,%eax /* hi-to-lo: PG,AM,WP,NE,ET,MP,PE */
        mov     %eax,%cr0
        jmp     1f
1:

#if defined(__x86_64__)

        /* Now in compatibility mode. Long-jump into 64-bit mode. */
        ljmp    $TRAMP_CS64,$SYM_TRAMP_PHYS(start64)

        .code64
start64:
        /* Jump to high mappings. */
        mov     high_start(%rip),%rax
        jmpq    *%rax

high_start:
        .quad   __high_start

#else /* !defined(__x86_64__) */

        /* Install relocated selectors. */
        lgdt    gdt_descr
        mov     $(__HYPERVISOR_DS),%eax
        mov     %eax,%ds
        mov     %eax,%es
        mov     %eax,%fs
        mov     %eax,%gs
        mov     %eax,%ss
        ljmp    $(__HYPERVISOR_CS),$__high_start

#endif
