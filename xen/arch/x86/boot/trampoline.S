/*
 * Trampoline code relocated to low memory.
 *
 * Care must taken when referencing symbols: they live in the relocated
 * trampoline and in the hypervisor binary. The hypervisor symbols can either
 * be accessed by their virtual address or by the physical address. When
 * using the physical address eventually the physical start address of the
 * hypervisor must be taken into account: after early boot the hypervisor
 * will copy itself to high memory and writes its physical start address to
 * trampoline_xen_phys_start in the low memory trampoline copy.
 *
 * Parts of the trampoline are needed for early boot only, while some other
 * parts are needed as long as the hypervisor is active (e.g. wakeup code
 * after suspend, bringup code for secondary cpus). The permanent parts should
 * not reference any temporary low memory trampoline parts as those parts are
 * not guaranteed to persist.
 */

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

/* Start of the permanent trampoline code. */

        .code16

/*
 * do_boot_cpu() programs the Startup-IPI to point here.  Due to the SIPI
 * format, the relocated entrypoint must be 4k aligned.
 *
 * It is entered in Real Mode, with %cs = trampoline_realmode_entry >> 4 and
 * %ip = 0.
 */
GLOBAL(trampoline_realmode_entry)
        mov     %cs,%ax
        mov     %ax,%ds
        movb    $0xA5,bootsym(trampoline_cpu_started)
        cld
        cli
        lidt    bootsym(idt_48)
        lgdt    bootsym(gdt_48)
        mov     $X86_CR0_PE, %ebx         # EBX != 0 indicates we are an AP
        mov     %ebx, %cr0                # Alias with CR0.PE for brevity

        ljmpl   $BOOT_CS32,$bootsym_rel(trampoline_protmode_entry,6)

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
        mov     $sym_offs(idle_pg_table),%eax
        add     bootsym_rel(trampoline_xen_phys_start,4,%eax)
        mov     %eax,%cr3

        /* Adjust IA32_MISC_ENABLE if needed (for NX enabling below). */
        mov     bootsym_rel(trampoline_misc_enable_off,4,%esi)
        mov     bootsym_rel(trampoline_misc_enable_off+4,4,%edi)
        mov     %esi,%eax
        or      %edi,%eax
        jz      1f
        mov     $MSR_IA32_MISC_ENABLE,%ecx
        rdmsr
        not     %esi
        not     %edi
        and     %esi,%eax
        and     %edi,%edx
        wrmsr
1:

        /* Set up EFER (Extended Feature Enable Register). */
        movl    $MSR_EFER,%ecx
        rdmsr
        or      bootsym_rel(trampoline_efer, 4, %eax)
        wrmsr

        mov     $(X86_CR0_PG | X86_CR0_AM | X86_CR0_WP | X86_CR0_NE |\
                  X86_CR0_ET | X86_CR0_MP | X86_CR0_PE), %eax
        mov     %eax,%cr0

        /* Now in compatibility mode. Long-jump into 64-bit mode. */
        ljmp    $BOOT_CS64,$bootsym_rel(start64,6)

        .code64
start64:
        /* Jump to high mappings. */
        movabs  $__high_start, %rdi
        jmpq    *%rdi

#include "video.h"
#include "wakeup.S"

        .balign 8
        .word   0
idt_48: .word   0, 0, 0 # base = limit = 0

trampoline_gdt:
        .word   0                  /* 0x0000: unused (reused for GDTR) */
gdt_48:
        .word   .Ltrampoline_gdt_end - trampoline_gdt - 1
        .long   bootsym_rel(trampoline_gdt, 4)

        .quad   0x00cf9b000000ffff /* 0x0008: ring 0 code, 32-bit mode */
        .quad   0x00af9b000000ffff /* 0x0010: ring 0 code, 64-bit mode */
        .quad   0x00cf93000000ffff /* 0x0018: ring 0 data */
        .quad   0x00009b000000ffff /* 0x0020: real-mode code @ BOOT_TRAMPOLINE */
        .quad   0x000093000000ffff /* 0x0028: real-mode data @ BOOT_TRAMPOLINE */
        .quad   0x00c0930000000fff /* 0x0030: ring 0 Xen data, 16M @ XEN */
.Ltrampoline_gdt_end:

        /* Relocations for trampoline Real Mode segments. */
        .pushsection .trampoline_rel, "a"
        .long   trampoline_gdt + BOOT_PSEUDORM_CS + 2 - .
        .long   trampoline_gdt + BOOT_PSEUDORM_DS + 2 - .
        .popsection

GLOBAL(trampoline_misc_enable_off)
        .quad   0

/* EFER OR-mask for boot paths.  This gets adjusted with NX when available. */
GLOBAL(trampoline_efer)
        .long   EFER_LME | EFER_SCE

GLOBAL(trampoline_xen_phys_start)
        .long   0

GLOBAL(trampoline_cpu_started)
        .byte   0

/* The first page of trampoline is permanent, the rest boot-time only. */
/* Reuse the boot trampoline on the 1st trampoline page as stack for wakeup. */
        .equ    wakeup_stack, trampoline_start + PAGE_SIZE
        .global wakeup_stack

/* From here on early boot only. */

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
#ifdef CONFIG_VIDEO
        call    video
#endif

        mov     $0x0200,%ax
        int     $0x16
        mov     %al,bootsym(kbd_shift_flags)

        /* Disable irqs before returning to protected mode. */
        cli

        /* Reset GDT and IDT. Some BIOSes clobber GDTR. */
        lidt    bootsym(idt_48)
        lgdt    bootsym(gdt_48)

        /* Enter protected mode, and flush insn queue. */
        mov     $X86_CR0_PE, %eax
        mov     %eax, %cr0

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

        .align  2
/* Keep in sync with cmdline.c:early_boot_opts_t type! */
early_boot_opts:
skip_realmode:
        .byte   0
opt_edd:
        .byte   0                               /* edd=on/off/skipmbr */
opt_edid:
        .byte   0                               /* EDID parsing option (force/no/default). */
/* Padding. */
        .byte   0

#ifdef CONFIG_VIDEO
boot_vid_mode:
        .word   VIDEO_80x25                     /* If we don't run at all, assume basic video mode 3 at 80x25. */
vesa_size:
        .word   0,0,0                           /* width x depth x height */
#endif

GLOBAL(kbd_shift_flags)
        .byte   0

rm_idt: .word   256*4-1, 0, 0

#include "mem.S"
#include "edd.S"
#ifdef CONFIG_VIDEO
#include "video.S"
#endif
