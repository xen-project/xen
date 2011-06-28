        .code16

/* NB. bootsym() is only usable in real mode, or via BOOT_PSEUDORM_DS. */
#undef bootsym
#define bootsym(s) ((s)-trampoline_start)

        .globl trampoline_realmode_entry
trampoline_realmode_entry:
        mov     %cs,%ax
        mov     %ax,%ds
        movb    $0xA5,bootsym(trampoline_cpu_started)
        cld
        cli
        lidt    bootsym(idt_48)
        lgdt    bootsym(gdt_48)
        mov     $1,%bl                    # EBX != 0 indicates we are an AP
        xor     %ax, %ax
        inc     %ax
        lmsw    %ax                       # CR0.PE = 1 (enter protected mode)
        ljmpl   $BOOT_CS32,$bootsym_phys(trampoline_protmode_entry)

idt_48: .word   0, 0, 0 # base = limit = 0
gdt_48: .word   6*8-1
        .long   bootsym_phys(trampoline_gdt)
trampoline_gdt:
        /* 0x0000: unused */
        .quad   0x0000000000000000
        /* 0x0008: ring 0 code, 32-bit mode */
        .quad   0x00cf9a000000ffff
        /* 0x0010: ring 0 code, 64-bit mode */
        .quad   0x00af9a000000ffff
        /* 0x0018: ring 0 data */
        .quad   0x00cf92000000ffff
        /* 0x0020: real-mode code @ BOOT_TRAMPOLINE */
        .long   0x0000ffff | ((BOOT_TRAMPOLINE & 0x00ffff) << 16)
        .long   0x00009a00 | ((BOOT_TRAMPOLINE & 0xff0000) >> 16)
        /* 0x0028: real-mode data @ BOOT_TRAMPOLINE */
        .long   0x0000ffff | ((BOOT_TRAMPOLINE & 0x00ffff) << 16)
        .long   0x00009200 | ((BOOT_TRAMPOLINE & 0xff0000) >> 16)

        .globl cpuid_ext_features
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
        mov     $X86_CR4_PAE,%ecx
        mov     %ecx,%cr4

        /* Load pagetable base register. */
        mov     $sym_phys(idle_pg_table),%eax
        add     bootsym_phys(trampoline_xen_phys_start),%eax
        mov     %eax,%cr3

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
        cmpb    $0,bootsym_phys(skip_realmode)
        jnz     .Lskip_realmode

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

        /* Load proper real-mode values into %cs, %ds, %es and %ss. */
        ljmp    $(BOOT_TRAMPOLINE>>4),$bootsym(1f)
1:      mov     $(BOOT_TRAMPOLINE>>4),%ax
        mov     %ax,%ds
        mov     %ax,%es
        mov     %ax,%ss

        /* Initialise stack pointer and IDT, and enable irqs. */
        mov     $bootsym(early_stack),%sp
        lidt    bootsym(rm_idt)
        sti

#if defined(__x86_64__)
        /*
         * Declare that our target operating mode is long mode.
         * Initialise 32-bit registers since some buggy BIOSes depend on it.
         */
        movl    $0xec00,%eax      # declare target operating mode
        movl    $0x0002,%ebx      # long mode
        int     $0x15
#endif

        /*
         * Do real-mode work:
         *  1. Get memory map.
         *  2. Get Enhanced Disk Drive (EDD) information.
         *  3. Set video mode.
         */
        call    get_memory_map
        call    get_edd
        call    video

        /* Disable irqs before returning to protected mode. */
        cli

        /* Reset GDT and IDT. Some BIOSes clobber GDTR. */
        lidt    bootsym(idt_48)
        lgdt    bootsym(gdt_48)

        /* Enter protected mode, and flush insn queue. */
        xor     %ax,%ax
        inc     %ax
        lmsw    %ax                       # CR0.PE = 1 (enter protected mode)

        /* Load proper protected-mode values into all segment registers. */
        ljmpl   $BOOT_CS32,$bootsym_phys(1f)
        .code32
1:      mov     $BOOT_DS,%eax
        mov     %eax,%ds
        mov     %eax,%es
        mov     %eax,%fs
        mov     %eax,%gs
        mov     %eax,%ss

.Lskip_realmode:
        /* EBX == 0 indicates we are the BP (Boot Processor). */
        xor     %ebx,%ebx

        /* Jump to the common bootstrap entry point. */
        jmp     trampoline_protmode_entry

skip_realmode:
        .byte   0

rm_idt: .word   256*4-1, 0, 0

#include "mem.S"
#include "edd.S"
#include "video.S"
#include "wakeup.S"

        .align  16
        .fill   PAGE_SIZE,1,0
early_stack:
