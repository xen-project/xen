#include <xen/multiboot.h>
#include <xen/multiboot2.h>
#include <public/xen.h>
#include <asm/asm_defns.h>
#include <asm/desc.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/msr.h>
#include <asm/cpufeature.h>

        .text
        .code32

#define sym_phys(sym)     ((sym) - __XEN_VIRT_START)

#define BOOT_CS32        0x0008
#define BOOT_CS64        0x0010
#define BOOT_DS          0x0018
#define BOOT_PSEUDORM_CS 0x0020
#define BOOT_PSEUDORM_DS 0x0028

#define MB2_HT(name)      (MULTIBOOT2_HEADER_TAG_##name)
#define MB2_TT(name)      (MULTIBOOT2_TAG_TYPE_##name)

        .macro mb2ht_args arg:req, args:vararg
        .long \arg
        .ifnb \args
        mb2ht_args \args
        .endif
        .endm

        .macro mb2ht_init type:req, req:req, args:vararg
        .align MULTIBOOT2_TAG_ALIGN
.Lmb2ht_init_start\@:
        .short \type
        .short \req
        .long .Lmb2ht_init_end\@ - .Lmb2ht_init_start\@
        .ifnb \args
        mb2ht_args \args
        .endif
.Lmb2ht_init_end\@:
        .endm

ENTRY(start)
        jmp     __start

        .align 4
multiboot1_header_start:       /*** MULTIBOOT1 HEADER ****/
#define MULTIBOOT_HEADER_FLAGS (MULTIBOOT_HEADER_MODS_ALIGNED | \
                                MULTIBOOT_HEADER_WANT_MEMORY)
        /* Magic number indicating a Multiboot header. */
        .long   MULTIBOOT_HEADER_MAGIC
        /* Flags to bootloader (see Multiboot spec). */
        .long   MULTIBOOT_HEADER_FLAGS
        /* Checksum: must be the negated sum of the first two fields. */
        .long   -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)
multiboot1_header_end:

/*** MULTIBOOT2 HEADER ****/
/* Some ideas are taken from grub-2.00/grub-core/tests/boot/kernel-i386.S file. */
        .align  MULTIBOOT2_HEADER_ALIGN

multiboot2_header_start:
        /* Magic number indicating a Multiboot2 header. */
        .long   MULTIBOOT2_HEADER_MAGIC
        /* Architecture: i386. */
        .long   MULTIBOOT2_ARCHITECTURE_I386
        /* Multiboot2 header length. */
        .long   .Lmultiboot2_header_end - multiboot2_header_start
        /* Multiboot2 header checksum. */
        .long   -(MULTIBOOT2_HEADER_MAGIC + MULTIBOOT2_ARCHITECTURE_I386 + \
                        (.Lmultiboot2_header_end - multiboot2_header_start))

        /* Multiboot2 information request tag. */
        mb2ht_init MB2_HT(INFORMATION_REQUEST), MB2_HT(REQUIRED), \
                   MB2_TT(BASIC_MEMINFO), MB2_TT(MMAP)

        /* Align modules at page boundry. */
        mb2ht_init MB2_HT(MODULE_ALIGN), MB2_HT(REQUIRED)

        /* Console flags tag. */
        mb2ht_init MB2_HT(CONSOLE_FLAGS), MB2_HT(OPTIONAL), \
                   MULTIBOOT2_CONSOLE_FLAGS_EGA_TEXT_SUPPORTED

        /* Framebuffer tag. */
        mb2ht_init MB2_HT(FRAMEBUFFER), MB2_HT(OPTIONAL), \
                   0, /* Number of the columns - no preference. */ \
                   0, /* Number of the lines - no preference. */ \
                   0  /* Number of bits per pixel - no preference. */

        /* Request that ExitBootServices() not be called. */
        mb2ht_init MB2_HT(EFI_BS), MB2_HT(OPTIONAL)

        /* EFI64 Multiboot2 entry point. */
        mb2ht_init MB2_HT(ENTRY_ADDRESS_EFI64), MB2_HT(OPTIONAL), \
                   sym_phys(__efi64_mb2_start)

        /* Multiboot2 header end tag. */
        mb2ht_init MB2_HT(END), MB2_HT(REQUIRED)
.Lmultiboot2_header_end:

        .section .init.rodata, "a", @progbits
        .align 4

        .word   0
gdt_boot_descr:
        .word   6*8-1
        .long   sym_phys(trampoline_gdt)
        .long   0 /* Needed for 64-bit lgdt */

.Lbad_cpu_msg: .asciz "ERR: Not a 64-bit CPU!"
.Lbad_ldr_msg: .asciz "ERR: Not a Multiboot bootloader!"
.Lbad_ldr_nbs: .asciz "ERR: Bootloader shutdown EFI x64 boot services!"
.Lbad_ldr_nst: .asciz "ERR: EFI SystemTable is not provided by bootloader!"
.Lbad_ldr_nih: .asciz "ERR: EFI ImageHandle is not provided by bootloader!"
.Lbad_efi_msg: .asciz "ERR: EFI IA-32 platforms are not supported!"

        .section .init.data, "aw", @progbits
        .align 4

vga_text_buffer:
        .long   0xb8000

efi_platform:
        .byte   0

        .section .init.text, "ax", @progbits

bad_cpu:
        mov     $(sym_phys(.Lbad_cpu_msg)),%esi # Error message
        jmp     .Lget_vtb
not_multiboot:
        mov     $(sym_phys(.Lbad_ldr_msg)),%esi # Error message
        jmp     .Lget_vtb
.Lmb2_no_st:
        /*
         * Here we are on EFI platform. vga_text_buffer was zapped earlier
         * because there is pretty good chance that VGA is unavailable.
         */
        mov     $(sym_phys(.Lbad_ldr_nst)),%esi # Error message
        jmp     .Lget_vtb
.Lmb2_no_ih:
        /* Ditto. */
        mov     $(sym_phys(.Lbad_ldr_nih)),%esi # Error message
        jmp     .Lget_vtb
.Lmb2_no_bs:
        /*
         * Ditto. Additionally, here there is a chance that Xen was started
         * via start label. Then reliable vga_text_buffer zap is impossible
         * in Multiboot2 scanning loop and we have to zero %edi below.
         */
        mov     $(sym_phys(.Lbad_ldr_nbs)),%esi # Error message
        xor     %edi,%edi                       # No VGA text buffer
        jmp     .Lsend_chr
.Lmb2_efi_ia_32:
        /*
         * Here we are on EFI IA-32 platform. Then reliable vga_text_buffer zap is
         * impossible in Multiboot2 scanning loop and we have to zero %edi below.
         */
        mov     $(sym_phys(.Lbad_efi_msg)),%esi # Error message
        xor     %edi,%edi                       # No VGA text buffer
        jmp     .Lsend_chr
.Lget_vtb:
        mov     sym_phys(vga_text_buffer),%edi
.Lsend_chr:
        mov     (%esi),%bl
        test    %bl,%bl        # Terminate on '\0' sentinel
        je      .Lhalt
        mov     $0x3f8+5,%dx   # UART Line Status Register
2:      in      %dx,%al
        test    $0x20,%al      # Test THR Empty flag
        je      2b
        mov     $0x3f8+0,%dx   # UART Transmit Holding Register
        mov     %bl,%al
        out     %al,%dx        # Send a character over the serial line
        test    %edi,%edi      # Is the VGA text buffer available?
        jz      .Lsend_chr
        movsb                  # Write a character to the VGA text buffer
        mov     $7,%al
        stosb                  # Write an attribute to the VGA text buffer
        jmp     .Lsend_chr
.Lhalt: hlt
        jmp     .Lhalt

        .code64

__efi64_mb2_start:
        /*
         * Multiboot2 spec says that here CPU is in 64-bit mode. However,
         * there is also guarantee that all code and data is always put
         * by the bootloader below 4 GiB. Hence, we can safely truncate
         * addresses to 32-bits in most cases below.
         */

        cld

        /* VGA is not available on EFI platforms. */
        movl   $0,vga_text_buffer(%rip)

        /* Check for Multiboot2 bootloader. */
        cmp     $MULTIBOOT2_BOOTLOADER_MAGIC,%eax
        je      .Lefi_multiboot2_proto

        /* Jump to not_multiboot after switching CPU to x86_32 mode. */
        lea     not_multiboot(%rip),%r15
        jmp     x86_32_switch

.Lefi_multiboot2_proto:
        /* Zero EFI SystemTable and EFI ImageHandle addresses. */
        xor     %esi,%esi
        xor     %edi,%edi

        /* Skip Multiboot2 information fixed part. */
        lea     (MB2_fixed_sizeof+MULTIBOOT2_TAG_ALIGN-1)(%rbx),%ecx
        and     $~(MULTIBOOT2_TAG_ALIGN-1),%ecx

.Lefi_mb2_tsize:
        /* Check Multiboot2 information total size. */
        mov     %ecx,%r8d
        sub     %ebx,%r8d
        cmp     %r8d,MB2_fixed_total_size(%rbx)
        jbe     .Lrun_bs

        /* Are EFI boot services available? */
        cmpl    $MULTIBOOT2_TAG_TYPE_EFI_BS,MB2_tag_type(%rcx)
        jne     .Lefi_mb2_st

        /* We are on EFI platform and EFI boot services are available. */
        incb    efi_platform(%rip)

        /*
         * Disable real mode and other legacy stuff which should not
         * be run on EFI platforms.
         */
        incb    skip_realmode(%rip)
        jmp     .Lefi_mb2_next_tag

.Lefi_mb2_st:
        /* Get EFI SystemTable address from Multiboot2 information. */
        cmpl    $MULTIBOOT2_TAG_TYPE_EFI64,MB2_tag_type(%rcx)
        cmove   MB2_efi64_st(%rcx),%rsi
        je      .Lefi_mb2_next_tag

        /* Get EFI ImageHandle address from Multiboot2 information. */
        cmpl    $MULTIBOOT2_TAG_TYPE_EFI64_IH,MB2_tag_type(%rcx)
        cmove   MB2_efi64_ih(%rcx),%rdi
        je      .Lefi_mb2_next_tag

        /* Is it the end of Multiboot2 information? */
        cmpl    $MULTIBOOT2_TAG_TYPE_END,MB2_tag_type(%rcx)
        je      .Lrun_bs

.Lefi_mb2_next_tag:
        /* Go to next Multiboot2 information tag. */
        add     MB2_tag_size(%rcx),%ecx
        add     $(MULTIBOOT2_TAG_ALIGN-1),%ecx
        and     $~(MULTIBOOT2_TAG_ALIGN-1),%ecx
        jmp     .Lefi_mb2_tsize

.Lrun_bs:
        /* Are EFI boot services available? */
        cmpb    $0,efi_platform(%rip)

        /* Jump to .Lmb2_no_bs after switching CPU to x86_32 mode. */
        lea     .Lmb2_no_bs(%rip),%r15
        jz      x86_32_switch

        /* Is EFI SystemTable address provided by boot loader? */
        test    %rsi,%rsi

        /* Jump to .Lmb2_no_st after switching CPU to x86_32 mode. */
        lea     .Lmb2_no_st(%rip),%r15
        jz      x86_32_switch

        /* Is EFI ImageHandle address provided by boot loader? */
        test    %rdi,%rdi

        /* Jump to .Lmb2_no_ih after switching CPU to x86_32 mode. */
        lea     .Lmb2_no_ih(%rip),%r15
        jz      x86_32_switch

        /*
         * Align the stack as UEFI spec requires. Keep it aligned
         * before efi_multiboot2() call by pushing/popping even
         * numbers of items on it.
         */
        and     $~15,%rsp

        /* Save Multiboot2 magic on the stack. */
        push    %rax

        /* Save EFI ImageHandle on the stack. */
        push    %rdi

        /*
         * Initialize BSS (no nasty surprises!).
         * It must be done earlier than in BIOS case
         * because efi_multiboot2() touches it.
         */
        lea     __bss_start(%rip),%edi
        lea     __bss_end(%rip),%ecx
        sub     %edi,%ecx
        shr     $3,%ecx
        xor     %eax,%eax
        rep stosq

        /* Keep the stack aligned. Do not pop a single item off it. */
        mov     (%rsp),%rdi

        /*
         * efi_multiboot2() is called according to System V AMD64 ABI:
         *   - IN:  %rdi - EFI ImageHandle, %rsi - EFI SystemTable.
         */
        call    efi_multiboot2

        /* Just pop an item from the stack. */
        pop     %rax

        /* Restore Multiboot2 magic. */
        pop     %rax

        /* Jump to trampoline_setup after switching CPU to x86_32 mode. */
        lea     trampoline_setup(%rip),%r15

x86_32_switch:
        mov     %r15,%rdi

        cli

        /* Initialize GDTR. */
        lgdt    gdt_boot_descr(%rip)

        /* Reload code selector. */
        pushq   $BOOT_CS32
        lea     cs32_switch(%rip),%edx
        push    %rdx
        lretq

        .code32

cs32_switch:
        /* Initialize basic data segments. */
        mov     $BOOT_DS,%edx
        mov     %edx,%ds
        mov     %edx,%es
        mov     %edx,%ss
        /* %esp is initialized later. */

        /* Load null descriptor to unused segment registers. */
        xor     %edx,%edx
        mov     %edx,%fs
        mov     %edx,%gs

        /* Disable paging. */
        mov     %cr0,%edx
        and     $(~X86_CR0_PG),%edx
        mov     %edx,%cr0

        /* Jump to earlier loaded address. */
        jmp     *%edi

__start:
        cld
        cli

        /* Initialise GDT and basic data segments. */
        lgdt    %cs:sym_phys(gdt_boot_descr)
        mov     $BOOT_DS,%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%ss

        /* Bootloaders may set multiboot{1,2}.mem_lower to a nonzero value. */
        xor     %edx,%edx

        /* Check for Multiboot2 bootloader. */
        cmp     $MULTIBOOT2_BOOTLOADER_MAGIC,%eax
        je      .Lmultiboot2_proto

        /* Check for Multiboot bootloader. */
        cmp     $MULTIBOOT_BOOTLOADER_MAGIC,%eax
        jne     not_multiboot

        /* Get mem_lower from Multiboot information. */
        testb   $MBI_MEMLIMITS,MB_flags(%ebx)

        /* Not available? BDA value will be fine. */
        cmovnz  MB_mem_lower(%ebx),%edx
        jmp     trampoline_bios_setup

.Lmultiboot2_proto:
        /* Skip Multiboot2 information fixed part. */
        lea     (MB2_fixed_sizeof+MULTIBOOT2_TAG_ALIGN-1)(%ebx),%ecx
        and     $~(MULTIBOOT2_TAG_ALIGN-1),%ecx

.Lmb2_tsize:
        /* Check Multiboot2 information total size. */
        mov     %ecx,%edi
        sub     %ebx,%edi
        cmp     %edi,MB2_fixed_total_size(%ebx)
        jbe     trampoline_bios_setup

        /* Get mem_lower from Multiboot2 information. */
        cmpl    $MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO,MB2_tag_type(%ecx)
        cmove   MB2_mem_lower(%ecx),%edx
        je      .Lmb2_next_tag

        /* EFI IA-32 platforms are not supported. */
        cmpl    $MULTIBOOT2_TAG_TYPE_EFI32,MB2_tag_type(%ecx)
        je      .Lmb2_efi_ia_32

        /* Bootloader shutdown EFI x64 boot services. */
        cmpl    $MULTIBOOT2_TAG_TYPE_EFI64,MB2_tag_type(%ecx)
        je      .Lmb2_no_bs

        /* Is it the end of Multiboot2 information? */
        cmpl    $MULTIBOOT2_TAG_TYPE_END,MB2_tag_type(%ecx)
        je      trampoline_bios_setup

.Lmb2_next_tag:
        /* Go to next Multiboot2 information tag. */
        add     MB2_tag_size(%ecx),%ecx
        add     $(MULTIBOOT2_TAG_ALIGN-1),%ecx
        and     $~(MULTIBOOT2_TAG_ALIGN-1),%ecx
        jmp     .Lmb2_tsize

trampoline_bios_setup:
        /* Set up trampoline segment 64k below EBDA */
        movzwl  0x40e,%ecx          /* EBDA segment */
        cmp     $0xa000,%ecx        /* sanity check (high) */
        jae     0f
        cmp     $0x4000,%ecx        /* sanity check (low) */
        jae     1f
0:
        movzwl  0x413,%ecx          /* use base memory size on failure */
        shl     $10-4,%ecx
1:
        /*
         * Compare the value in the BDA with the information from the
         * multiboot structure (if available) and use the smallest.
         */
        cmp     $0x100,%edx         /* is the multiboot value too small? */
        jb      2f                  /* if so, do not use it */
        shl     $10-4,%edx
        cmp     %ecx,%edx           /* compare with BDA value */
        cmovb   %edx,%ecx           /* and use the smaller */

2:
        /* Reserve memory for the trampoline and the low-memory stack. */
        sub     $((TRAMPOLINE_SPACE+TRAMPOLINE_STACK_SPACE)>>4),%ecx

        /* From arch/x86/smpboot.c: start_eip had better be page-aligned! */
        xor     %cl, %cl
        shl     $4, %ecx
        mov     %ecx,sym_phys(trampoline_phys)

trampoline_setup:
        mov     sym_phys(trampoline_phys),%ecx

        /* Get bottom-most low-memory stack address. */
        add     $TRAMPOLINE_SPACE,%ecx

        /* Save the Multiboot info struct (after relocation) for later use. */
        mov     $sym_phys(cpu0_stack)+1024,%esp
        push    %ecx                /* Bottom-most low-memory stack address. */
        push    %ebx                /* Multiboot information address. */
        push    %eax                /* Multiboot magic. */
        call    reloc
        mov     %eax,sym_phys(multiboot_ptr)

        /*
         * Now trampoline_phys points to the following structure (lowest address
         * is at the bottom):
         *
         * +------------------------+
         * | TRAMPOLINE_STACK_SPACE |
         * +------------------------+
         * |        mbi data        |
         * +- - - - - - - - - - - - +
         * |    TRAMPOLINE_SPACE    |
         * +------------------------+
         *
         * mbi data grows downwards from the highest address of TRAMPOLINE_SPACE
         * region to the end of the trampoline. The rest of TRAMPOLINE_SPACE is
         * reserved for trampoline code and data.
         */

        /*
         * Do not zero BSS on EFI platform here.
         * It was initialized earlier.
         */
        cmpb    $0,sym_phys(efi_platform)
        jnz     1f

        /* Initialize BSS (no nasty surprises!). */
        mov     $sym_phys(__bss_start),%edi
        mov     $sym_phys(__bss_end),%ecx
        sub     %edi,%ecx
        xor     %eax,%eax
        shr     $2,%ecx
        rep stosl

1:
        /* Interrogate CPU extended features via CPUID. */
        mov     $0x80000000,%eax
        cpuid
        shld    $16,%eax,%ecx
        xor     %edx,%edx
        cmp     $0x8000,%cx         # any function @ 0x8000xxxx?
        jne     1f
        cmp     $0x80000000,%eax    # any function > 0x80000000?
        jbe     1f
        mov     $0x80000001,%eax
        cpuid
1:      mov     %edx,sym_phys(cpuid_ext_features)
        mov     %edx,sym_phys(boot_cpu_data)+CPUINFO_FEATURE_OFFSET(X86_FEATURE_LM)

        /* Check for availability of long mode. */
        bt      $cpufeat_bit(X86_FEATURE_LM),%edx
        jnc     bad_cpu

        /* Stash TSC to calculate a good approximation of time-since-boot */
        rdtsc
        mov     %eax,sym_phys(boot_tsc_stamp)
        mov     %edx,sym_phys(boot_tsc_stamp+4)

        /* Apply relocations to bootstrap trampoline. */
        mov     sym_phys(trampoline_phys),%edx
        mov     $sym_phys(__trampoline_rel_start),%edi
1:
        mov     (%edi),%eax
        add     %edx,(%edi,%eax)
        add     $4,%edi
        cmp     $sym_phys(__trampoline_rel_stop),%edi
        jb      1b

        /* Patch in the trampoline segment. */
        shr     $4,%edx
        mov     $sym_phys(__trampoline_seg_start),%edi
1:
        mov     (%edi),%eax
        mov     %dx,(%edi,%eax)
        add     $4,%edi
        cmp     $sym_phys(__trampoline_seg_stop),%edi
        jb      1b

        /* Do not parse command line on EFI platform here. */
        cmpb    $0,sym_phys(efi_platform)
        jnz     1f

        /* Bail if there is no command line to parse. */
        mov     sym_phys(multiboot_ptr),%ebx
        testl   $MBI_CMDLINE,MB_flags(%ebx)
        jz      1f

        pushl   $sym_phys(early_boot_opts)
        pushl   MB_cmdline(%ebx)
        call    cmdline_parse_early

1:
        /* Switch to low-memory stack which lives at the end of trampoline region. */
        mov     sym_phys(trampoline_phys),%edi
        lea     TRAMPOLINE_SPACE+TRAMPOLINE_STACK_SPACE(%edi),%esp
        lea     trampoline_boot_cpu_entry-trampoline_start(%edi),%eax
        pushl   $BOOT_CS32
        push    %eax

        /* Copy bootstrap trampoline to low memory, below 1MB. */
        mov     $sym_phys(trampoline_start),%esi
        mov     $((trampoline_end - trampoline_start) / 4),%ecx
        rep movsl

        /* Jump into the relocated trampoline. */
        lret

cmdline_parse_early:
#include "cmdline.S"

reloc:
#include "reloc.S"

ENTRY(trampoline_start)
#include "trampoline.S"
ENTRY(trampoline_end)

#include "x86_64.S"
