        .code16

/* NB. bootsym() is only usable in real mode, or via BOOT_PSEUDORM_DS. */
#undef bootsym
#define bootsym(s) ((s)-trampoline_start)

#define bootsym_rel(sym, off, opnd...)     \
        bootsym(sym),##opnd;               \
111:;                                      \
        .pushsection .trampoline_rel, "a"; \
        .long 111b - (off) - .;            \
        .popsection

#define bootsym_segrel(sym, off)           \
        $0,$bootsym(sym);                  \
111:;                                      \
        .pushsection .trampoline_seg, "a"; \
        .long 111b - (off) - .;            \
        .popsection

GLOBAL(trampoline_realmode_entry)
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
        ljmpl   $BOOT_CS32,$bootsym_rel(trampoline_protmode_entry,6)

idt_48: .word   0, 0, 0 # base = limit = 0
gdt_48: .word   6*8-1
        .long   bootsym_rel(trampoline_gdt,4)
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
        .long   0x0000ffff
        .long   0x00009a00
        /* 0x0028: real-mode data @ BOOT_TRAMPOLINE */
        .long   0x0000ffff
        .long   0x00009200

        .pushsection .trampoline_rel, "a"
        .long   trampoline_gdt + BOOT_PSEUDORM_CS + 2 - .
        .long   trampoline_gdt + BOOT_PSEUDORM_DS + 2 - .
        .popsection

GLOBAL(cpuid_ext_features)
        .long   0

GLOBAL(trampoline_xen_phys_start)
        .long   0

GLOBAL(trampoline_cpu_started)
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
        add     bootsym_rel(trampoline_xen_phys_start,4,%eax)
        mov     %eax,%cr3

        /* Set up EFER (Extended Feature Enable Register). */
        mov     bootsym_rel(cpuid_ext_features,4,%edi)
        test    $0x20100800,%edi /* SYSCALL/SYSRET, No Execute, Long Mode? */
        jz      .Lskip_efer
        movl    $MSR_EFER,%ecx
        rdmsr
        btsl    $_EFER_LME,%eax /* Long Mode      */
        btsl    $_EFER_SCE,%eax /* SYSCALL/SYSRET */
        btl     $20,%edi        /* No Execute?    */
        jnc     1f
        btsl    $_EFER_NX,%eax  /* No Execute     */
1:      wrmsr
.Lskip_efer:

        mov     $0x80050033,%eax /* hi-to-lo: PG,AM,WP,NE,ET,MP,PE */
        mov     %eax,%cr0
        jmp     1f
1:

        /* Now in compatibility mode. Long-jump into 64-bit mode. */
        ljmp    $BOOT_CS64,$bootsym_rel(start64,6)

        .code64
start64:
        /* Jump to high mappings. */
        movabs  $__high_start,%rax
        jmpq    *%rax

        .code32
trampoline_boot_cpu_entry:
        cmpb    $0,bootsym_rel(skip_realmode,5)
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
        ljmp    bootsym_segrel(1f,2)
1:      mov     %cs,%ax
        mov     %ax,%ds
        mov     %ax,%es
        mov     %ax,%ss

        /* Initialise stack pointer and IDT, and enable irqs. */
        xor     %esp,%esp
        lidt    bootsym(rm_idt)
        sti

        /*
         * Declare that our target operating mode is long mode.
         * Initialise 32-bit registers since some buggy BIOSes depend on it.
         */
        xor     %ecx,%ecx
        xor     %edx,%edx
        xor     %esi,%esi
        xor     %edi,%edi
        xor     %ebp,%ebp
        movl    $0xec00,%eax      # declare target operating mode
        movl    $0x0002,%ebx      # long mode
        int     $0x15

        /*
         * Do real-mode work:
         *  1. Get memory map.
         *  2. Get Enhanced Disk Drive (EDD) information.
         *  3. Set video mode.
         *  4. Get keyboard shift flags.
         */
        call    get_memory_map
        call    get_edd
        call    video

        mov     $0x0200,%ax
        int     $0x16
        mov     %al,bootsym(kbd_shift_flags)

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
        ljmpl   $BOOT_CS32,$bootsym_rel(1f,6)
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

GLOBAL(kbd_shift_flags)
        .byte   0

rm_idt: .word   256*4-1, 0, 0

#include "mem.S"
#include "edd.S"
#include "video.S"
#include "wakeup.S"
