        .code16

/* NB. bootsym() is only usable in real mode, or via BOOT_PSEUDORM_DS. */
#undef bootsym
#define bootsym(s) ((s)-trampoline_start)

        .globl trampoline_realmode_entry
trampoline_realmode_entry:
        nop                               # We use this byte as a progress flag
        movb    $0xA5,bootsym(trampoline_cpu_started)
        cld
        cli
        lidt    %cs:bootsym(idt_48)
        lgdt    %cs:bootsym(gdt_48)
        xor     %ax, %ax
        inc     %ax
        lmsw    %ax                       # CR0.PE = 1 (enter protected mode)
        mov     $1,%bl                    # EBX != 0 indicates we are an AP
        jmp     1f
1:      ljmpl   $BOOT_CS32,$bootsym_phys(trampoline_protmode_entry)

idt_48: .word   0, 0, 0 # base = limit = 0
gdt_48: .word   6*8-1
        .long   bootsym_phys(trampoline_gdt)
trampoline_gdt:
        .quad   0x0000000000000000     /* 0x0000: unused */
        .quad   0x00cf9a000000ffff     /* 0x0008: ring 0 code, 32-bit mode */
        .quad   0x00af9a000000ffff     /* 0x0010: ring 0 code, 64-bit mode */
        .quad   0x00cf92000000ffff     /* 0x0018: ring 0 data */
        .quad   0x00009a090000ffff     /* 0x0020: real-mode code @ 0x90000 */
        .quad   0x000092090000ffff     /* 0x0028: real-mode data @ 0x90000 */

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
        mov     $BOOT_DS,%eax
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
        mov     $sym_phys(idle_pg_table),%eax
        add     bootsym_phys(trampoline_xen_phys_start),%eax
        mov     %eax,%cr3

#if CONFIG_PAGING_LEVELS != 2
        /* Set up EFER (Extended Feature Enable Register). */
        mov     bootsym_phys(cpuid_ext_features),%edi
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
        ljmp    $BOOT_CS64,$bootsym_phys(start64)

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

        .code32
trampoline_boot_cpu_entry:
        /* Load pseudo-real-mode segments. */
        mov     $BOOT_PSEUDORM_DS,%eax
        mov     %eax,%ds
        mov     %eax,%es
        mov     %eax,%fs
        mov     %eax,%gs
        mov     %eax,%ss

        /* Switch to pseudo-rm CS, enter real mode, and flush insn queue. */
        mov     %cr0,%eax
        dec     %eax
        ljmp    $BOOT_PSEUDORM_CS,$bootsym(1f)
        .code16
1:      mov     %eax,%cr0                 # CR0.PE = 0 (leave protected mode)
        jmp     1f

        /* Load proper real-mode values into %cs, %ds, %es and %ss. */
1:      ljmp    $(BOOT_TRAMPOLINE>>4),$bootsym(1f)
1:      mov     $(BOOT_TRAMPOLINE>>4),%ax
        mov     %ax,%ds
        mov     %ax,%es
        mov     %ax,%ss

        /* Stack grows down from 0x9200. Initialise IDT and enable irqs. */
        mov     $0x2000,%sp
        lidt    bootsym(rm_idt)
        sti

        /*
         * Do real-mode work:
         *  1. Get memory map.
         */
        call    get_memory_map

        /* Disable irqs before returning to protected mode. */
        cli

        /* Enter protected mode, and flush insn queue. */
        xor     %ax,%ax
        inc     %ax
        lmsw    %ax                       # CR0.PE = 1 (enter protected mode)
        jmp     1f

        /* Load proper protected-mode values into all segment registers. */
1:      ljmpl   $BOOT_CS32,$bootsym_phys(1f)
        .code32
1:      mov     $BOOT_DS,%eax
        mov     %eax,%ds
        mov     %eax,%es
        mov     %eax,%fs
        mov     %eax,%gs
        mov     %eax,%ss

        /* EBX == 0 indicates we are the BP (Boot Processor). */
        xor     %ebx,%ebx

        /* Jump to the common bootstrap entry point. */
        jmp     trampoline_protmode_entry

rm_idt: .word   256*4-1, 0, 0

#include "mem.S"
