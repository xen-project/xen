        .code16

#define wakesym(sym) (sym - wakeup_start)

/*
 * acpi_sleep_prepare() programs the S3 wakeup vector to point here.
 *
 * The ACPI spec says that we shall be entered in Real Mode with:
 *   %cs = wakeup_start >> 4
 *   %ip = wakeup_start & 0xf
 *
 * As wakeup_start is 16-byte aligned, %ip is 0 in practice.
 */
ENTRY(wakeup_start)
        cli
        cld

        # setup data segment
        movw    %cs, %ax
        movw    %ax, %ds
        movw    %ax, %ss        # A stack required for BIOS call
        movw    $wakesym(wakeup_stack), %sp

        pushl   $0              # Kill dangerous flag early
        popfl

        # check magic number
        movl    wakesym(real_magic), %eax
        cmpl    $0x12345678, %eax
        jne     bogus_real_magic

        # for acpi_sleep=s3_bios
        testb   $1, wakesym(video_flags)
        jz      1f
        lcall   $0xc000, $3
        movw    %cs, %ax        # In case messed by BIOS
        movw    %ax, %ds
        movw    %ax, %ss        # Need this? How to ret if clobbered?

1:      # for acpi_sleep=s3_mode
        testb   $2, wakesym(video_flags)
        jz      1f
        movw    wakesym(video_mode), %ax
        call    mode_setw

1:      # Show some progress if VGA is resumed
        movw    $0xb800, %ax
        movw    %ax, %fs
        movw    $0x0e00 + 'L', %fs:(0x10)

        lidt    wakesym(idt_48)
        lgdt    wakesym(gdt_48)

        mov     $X86_CR0_PE, %eax
        mov     %eax, %cr0

        ljmpl   $BOOT_CS32, $bootsym_rel(wakeup_32, 6)

# Setting of user mode (AX=mode ID) => CF=success
mode_setw:
        movw    %ax, %bx
        cmpb    $VIDEO_FIRST_VESA>>8, %ah
        jnc     check_vesaw

setbadw: clc
        ret

check_vesaw:
        subb    $VIDEO_FIRST_VESA>>8, %bh
        orb     $0x40, %bh                      # Use linear frame buffer
        movw    $0x4f02, %ax                    # VESA BIOS mode set call
        int     $0x10
        cmpw    $0x004f, %ax                    # AL=4f if implemented
        jnz     setbadw                         # AH=0 if OK

        stc
        ret

bogus_real_magic:
        movw    $0x0e00 + 'B', %fs:(0x12)
        jmp     bogus_real_magic

        .align 4
real_magic:     .long 0x12345678
video_mode:     .word 0
GLOBAL(video_flags)
        .byte 0

        .code32

        # Now in protect mode, with paging disabled
        # Add offset for any reference to xen specific symbols

wakeup_32:
        /* Set up segment registers and initial stack for protected mode */
        mov     $BOOT_DS, %eax
        mov     %eax, %ds
        mov     %eax, %ss
        mov     $bootsym_rel(wakeup_stack, 4, %esp)

        # check saved magic again
        mov     $sym_offs(saved_magic),%eax
        add     bootsym_rel(trampoline_xen_phys_start, 4, %eax)
        mov     (%eax), %eax
        cmp     $0x9abcdef0, %eax
        jne     bogus_saved_magic
        
        /* fpu init? */

        /* Initialise CR4. */
        mov     $X86_CR4_PAE, %ecx
        mov     %ecx, %cr4

        /* Load pagetable base register */
        mov     $sym_offs(idle_pg_table),%eax
        add     bootsym_rel(trampoline_xen_phys_start,4,%eax)
        mov     %eax,%cr3

        /* Reapply IA32_MISC_ENABLE modifications from early_init_intel(). */
        mov     bootsym_rel(trampoline_misc_enable_off, 4, %esi)
        mov     bootsym_rel(trampoline_misc_enable_off + 4, 4, %edi)
        mov     %esi, %eax
        or      %edi, %eax
        jz      1f
        mov     $MSR_IA32_MISC_ENABLE, %ecx
        rdmsr
        not     %esi
        not     %edi
        and     %esi, %eax
        and     %edi, %edx
        wrmsr
1:

        /* Set up EFER (Extended Feature Enable Register). */
        movl    $MSR_EFER,%ecx
        rdmsr
        or      bootsym_rel(trampoline_efer, 4, %eax)
        wrmsr

        wbinvd

        /* Enable paging and flush prefetch queue */
        mov     $0x80050033,%eax /* hi-to-lo: PG,AM,WP,NE,ET,MP,PE */
        mov     %eax,%cr0
        jmp     1f
1:

        /* Now in compatibility mode. Long-jump to 64-bit mode */
        ljmp    $BOOT_CS64, $bootsym_rel(wakeup_64,6)

        .code64
wakeup_64:
        /* Jump to high mappings and the higher-level wakeup code. */
        movabs  $__ret_point, %rbx
        jmp     *%rbx

bogus_saved_magic:
        movw    $0x0e00 + 'S', 0xb8014
        jmp     bogus_saved_magic

/* Stack for wakeup: rest of first trampoline page. */
ENTRY(wakeup_stack_start)
