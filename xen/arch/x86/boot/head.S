#include <xen/lib.h>
#include <xen/multiboot.h>
#include <xen/multiboot2.h>
#include <public/xen.h>
#include <asm/asm_defns.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/msr-index.h>
#include <asm/cpufeature.h>
#include <asm/trampoline.h>

#include <public/elfnote.h>

#define ENTRY(name)                             \
  .align CONFIG_FUNCTION_ALIGNMENT, CODE_FILL;  \
  GLOBAL(name)
#define GLOBAL(name)                            \
  .globl name;                                  \
  .hidden name;                                 \
  name:

        .section .text.header, "ax", @progbits
        .code32

#define sym_offs(sym)     ((sym) - __XEN_VIRT_START)
#define sym_esi(sym)      sym_offs(sym)(%esi)

#define BOOT_CS32        0x0008
#define BOOT_CS64        0x0010
#define BOOT_DS          0x0018
#define BOOT_PSEUDORM_CS 0x0020
#define BOOT_PSEUDORM_DS 0x0028

#define MB2_HT(name)      (MULTIBOOT2_HEADER_TAG_##name)
#define MB2_TT(name)      (MULTIBOOT2_TAG_TYPE_##name)

#define XEN_HVM_START_MAGIC_VALUE 0x336ec578

        .macro mb2ht_args arg:req, args:vararg
        .long \arg
        .ifnb \args
        mb2ht_args \args
        .endif
        .endm

        .macro mb2ht_init type:req, req:req, args:vararg
        .balign MULTIBOOT2_TAG_ALIGN, 0xc2 /* Avoid padding with long nops. */
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

        .balign 4
multiboot1_header:             /*** MULTIBOOT1 HEADER ****/
#define MULTIBOOT_HEADER_FLAGS (MULTIBOOT_HEADER_MODS_ALIGNED | \
                                MULTIBOOT_HEADER_WANT_MEMORY)
        /* Magic number indicating a Multiboot header. */
        .long   MULTIBOOT_HEADER_MAGIC
        /* Flags to bootloader (see Multiboot spec). */
        .long   MULTIBOOT_HEADER_FLAGS
        /* Checksum: must be the negated sum of the first two fields. */
        .long   -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)

        .size multiboot1_header, . - multiboot1_header
        .type multiboot1_header, @object

/*** MULTIBOOT2 HEADER ****/
/* Some ideas are taken from grub-2.00/grub-core/tests/boot/kernel-i386.S file. */
        .balign MULTIBOOT2_HEADER_ALIGN, 0xc2  /* Avoid padding the MB1 header with long nops. */

multiboot2_header:
        /* Magic number indicating a Multiboot2 header. */
        .long   MULTIBOOT2_HEADER_MAGIC
        /* Architecture: i386. */
        .long   MULTIBOOT2_ARCHITECTURE_I386
        /* Multiboot2 header length. */
        .long   .Lmultiboot2_header_end - multiboot2_header
        /* Multiboot2 header checksum. */
        .long   -(MULTIBOOT2_HEADER_MAGIC + MULTIBOOT2_ARCHITECTURE_I386 + \
                        (.Lmultiboot2_header_end - multiboot2_header))

        /* Multiboot2 information request tag. */
        mb2ht_init MB2_HT(INFORMATION_REQUEST), MB2_HT(REQUIRED), \
                   MB2_TT(BASIC_MEMINFO), MB2_TT(MMAP)

        /* Align modules at page boundry. */
        mb2ht_init MB2_HT(MODULE_ALIGN), MB2_HT(REQUIRED)

        /* Load address preference. */
        mb2ht_init MB2_HT(RELOCATABLE), MB2_HT(OPTIONAL), \
                   sym_offs(start), /* Min load address. */ \
                   0xffffffff, /* The end of image max load address (4 GiB - 1). */ \
                   0x200000, /* Load address alignment (2 MiB). */ \
                   MULTIBOOT2_LOAD_PREFERENCE_HIGH

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
                   sym_offs(__efi64_mb2_start)

        /* Multiboot2 header end tag. */
        mb2ht_init MB2_HT(END), MB2_HT(REQUIRED)
.Lmultiboot2_header_end:

        .size multiboot2_header, . - multiboot2_header
        .type multiboot2_header, @object

        .section .init.rodata, "a", @progbits

.Lbad_cpu_msg: .asciz "ERR: Not a 64-bit CPU!"
.Lbad_ldr_msg: .asciz "ERR: Not a Multiboot bootloader!"
.Lbad_ldr_nbs: .asciz "ERR: Bootloader shutdown EFI x64 boot services!"
.Lbad_efi_msg: .asciz "ERR: EFI IA-32 platforms are not supported!"
.Lbag_alg_msg: .asciz "ERR: Xen must be loaded at a 2Mb boundary!"
.Lno_nx_msg:   .asciz "ERR: Not an NX-capable CPU!"

        .section .init.data, "aw", @progbits
        .align 4

        .word   0
gdt_boot_descr:
        .word   .Ltrampoline_gdt_end - trampoline_gdt - 1
gdt_boot_base:
        .long   sym_offs(trampoline_gdt)
        .long   0 /* Needed for 64-bit lgdt */

vga_text_buffer:
        .long   0xb8000

efi_platform:
        .byte   0

        .section .init.text, "ax", @progbits

early_error: /* Here to improve the disassembly. */

.Lbad_cpu:
        mov     $sym_offs(.Lbad_cpu_msg), %ecx
        jmp     .Lget_vtb
.Lnot_multiboot:
        mov     $sym_offs(.Lbad_ldr_msg), %ecx
        jmp     .Lget_vtb
.Lnot_aligned:
        mov     $sym_offs(.Lbag_alg_msg), %ecx
        jmp     .Lget_vtb
#ifdef CONFIG_REQUIRE_NX
.Lno_nx:
        mov     $sym_offs(.Lno_nx_msg), %ecx
        jmp     .Lget_vtb
#endif
.Lmb2_no_bs:
        /*
         * Ditto. Additionally, here there is a chance that Xen was started
         * via start label. Then reliable vga_text_buffer zap is impossible
         * in Multiboot2 scanning loop and we have to zero %edi below.
         */
        mov     $sym_offs(.Lbad_ldr_nbs), %ecx
        xor     %edi,%edi                       # No VGA text buffer
        jmp     .Lprint_err
.Lmb2_efi_ia_32:
        /*
         * Here we are on EFI IA-32 platform. Then reliable vga_text_buffer zap is
         * impossible in Multiboot2 scanning loop and we have to zero %edi below.
         */
        mov     $sym_offs(.Lbad_efi_msg), %ecx
        xor     %edi,%edi                       # No VGA text buffer
        jmp     .Lprint_err
.Ldirect_error:
        mov     sym_esi(vga_text_buffer), %edi
        mov     %eax, %esi
        jmp     1f
.Lget_vtb:
        mov     sym_esi(vga_text_buffer), %edi
.Lprint_err:
        add     %ecx, %esi     # Add string offset to relocation base.
        # NOTE: No further use of sym_esi() till the end of the "function"!
1:
        lodsb
        test    %al,%al        # Terminate on '\0' sentinel
        je      .Lhalt
        mov     $0x3f8+5,%dx   # UART Line Status Register
        mov     %al,%bl
2:      in      %dx,%al
        test    $0x20,%al      # Test THR Empty flag
        je      2b
        mov     $0x3f8+0,%dx   # UART Transmit Holding Register
        mov     %bl,%al
        out     %al,%dx        # Send a character over the serial line
        test    %edi,%edi      # Is the VGA text buffer available?
        jz      1b
        stosb                  # Write a character to the VGA text buffer
        mov     $7,%al
        stosb                  # Write an attribute to the VGA text buffer
        jmp     1b
.Lhalt: hlt
        jmp     .Lhalt

        .size early_error, . - early_error
        .type early_error, @function

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

        /*
         * Align the stack as UEFI spec requires. Keep it aligned
         * before efi_multiboot2_prelude() call by pushing/popping even
         * numbers of items on it.
         */
        and     $~15, %rsp

        /* Save magic number, we need it later but we need to use %eax. */
        mov     %eax, %edx

        /*
         * Initialize BSS (no nasty surprises!).
         * It must be done earlier than in BIOS case
         * because efi_multiboot2_prelude() touches it.
         */
        lea     __bss_start(%rip), %edi
        lea     __bss_end(%rip), %ecx
        sub     %edi, %ecx
        shr     $3, %ecx
        xor     %eax, %eax
        rep stosq

        /*
         * Spill MB2 magic.
         * Spill the pointer too, to keep the stack aligned.
         */
        push    %rdx
        push    %rbx

        /*
         * efi_multiboot2_prelude() is called according to System V AMD64 ABI:
         *   - IN:  %edi - Multiboot2 magic,
         *          %rsi - Multiboot2 pointer.
         *   - OUT: %rax - error string.
         */
        mov     %edx, %edi
        mov     %rbx, %rsi
        call    efi_multiboot2_prelude
        lea     .Ldirect_error(%rip), %r15
        test    %rax, %rax
        jnz     x86_32_switch

        /* Restore Multiboot2 pointer and magic. */
        pop     %rbx
        pop     %rax

        /*
         * efi_multiboot2_prelude() is happy that we're on EFI platform.  Skip
         * the BIOS initialisation path.
         */
        movb    $1, efi_platform(%rip)
        movb    $1, skip_realmode(%rip)

        /* Jump to trampoline_setup after switching CPU to x86_32 mode. */
        lea     trampoline_setup(%rip),%r15

x86_32_switch:
        mov     %r15,%rdi

        /* Store Xen image load base address in place accessible for 32-bit code. */
        lea     __image_base__(%rip),%esi

        cli

        /* Initialize GDTR. */
        add     %esi,gdt_boot_base(%rip)
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

#ifdef CONFIG_PVH_GUEST
ELFNOTE(Xen, XEN_ELFNOTE_PHYS32_ENTRY, .long sym_offs(__pvh_start))

__pvh_start:
        mov     $XEN_HVM_START_MAGIC_VALUE, %eax
        /*
         * Fall through into BIOS code.
         * We will use %eax to distinguish we came from PVH entry point.
         */
#endif /* CONFIG_PVH_GUEST */

__start:
        cli
        cld

        /*
         * Multiboot (both 1 and 2) and PVH specify the stack pointer as
         * undefined.  This is unhelpful for relocatable images, where one
         * call (i.e. push) is required to calculate the image's load address.
         *
         * During BIOS boot, there is one area of memory we know about with
         * reasonable confidence that it isn't overlapped by Xen, and that's
         * the Multiboot info structure in %ebx.  Use it as a temporary stack.
         *
         * During PVH boot use info structure in %ebx.
         */

        /* Preserve the field we're about to clobber. */
        mov     (%ebx), %edx
        lea     4(%ebx), %esp

        /* Calculate the load base address. */
        call    1f
1:      pop     %esi
        sub     $sym_offs(1b), %esi

        /* Restore the clobbered field. */
        mov     %edx, (%ebx)

        /* Set up stack. */
        lea     STACK_SIZE - CPUINFO_sizeof + sym_esi(cpu0_stack), %esp

        /* Initialize GDTR and basic data segments. */
        add     %esi, sym_esi(gdt_boot_base)
        lgdt    sym_esi(gdt_boot_descr)

        mov     $BOOT_DS, %ecx
        mov     %ecx, %ds
        mov     %ecx, %es
        mov     %ecx, %ss
        mov     %ecx, %fs
        mov     %ecx, %gs

        /* Initialise the BSS.  Preserve %eax (BOOTLOADER_MAGIC). */
        mov     %eax, %ebp

        lea     sym_esi(__bss_start), %edi
        lea     sym_esi(__bss_end), %ecx
        sub     %edi, %ecx
        xor     %eax, %eax
        shr     $2, %ecx
        rep stosl

        mov     %ebp, %eax

#ifdef CONFIG_PVH_GUEST
        cmp     $XEN_HVM_START_MAGIC_VALUE, %eax
        jne     1f

        mov     %ebx, sym_esi(pvh_start_info_pa)

        /* Force xen console.  Will revert to user choice in init code. */
        movb    $-1, sym_esi(opt_console_xen)

        /* Skip bootloader setup and bios setup, go straight to trampoline */
        movb    $1, sym_esi(pvh_boot)
        movb    $1, sym_esi(skip_realmode)

        /* Set trampoline_phys to use mfn 1 to avoid having a mapping at VA 0 */
        movl    $PAGE_SIZE, sym_esi(trampoline_phys)
        jmp     trampoline_setup
1:
#endif /* CONFIG_PVH_GUEST */

        /* Bootloaders may set multiboot{1,2}.mem_lower to a nonzero value. */
        xor     %edx,%edx

        /* Check for Multiboot2 bootloader. */
        cmp     $MULTIBOOT2_BOOTLOADER_MAGIC,%eax
        je      .Lmultiboot2_proto

        /* Check for Multiboot bootloader. */
        cmp     $MULTIBOOT_BOOTLOADER_MAGIC,%eax
        jne     .Lnot_multiboot

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
        /*
         * Called on legacy BIOS platforms only.
         */

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
        sub     $TRAMPOLINE_SIZE >> 4, %ecx

        /* From arch/x86/smpboot.c: start_eip had better be page-aligned! */
        xor     %cl, %cl
        shl     $4, %ecx
        mov     %ecx,sym_esi(trampoline_phys)

trampoline_setup:
        /*
         * Called on legacy BIOS and EFI platforms.
         */

        /* Save Xen image load base address for later use. */
        mov     %esi, sym_esi(xen_phys_start)
        mov     %esi, sym_esi(trampoline_xen_phys_start)

        /* Save Multiboot / PVH info struct (after relocation) for later use. */
        mov     %ebx, %edx          /* Multiboot / PVH information address. */
        /*      reloc(magic/eax, info/edx) using fastcall. */
        call    reloc

#ifdef CONFIG_PVH_GUEST
        cmpb    $0, sym_esi(pvh_boot)
        je      1f
        mov     %eax, sym_esi(pvh_start_info_pa)
        jmp     2f
#endif
1:
        mov     %eax, sym_esi(multiboot_ptr)
2:

        /* Interrogate CPU extended features via CPUID. */
        mov     $1, %eax
        cpuid
        mov     %ecx, CPUINFO_FEATURE_OFFSET(X86_FEATURE_HYPERVISOR) + sym_esi(boot_cpu_data)

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
1:      mov     %edx, CPUINFO_FEATURE_OFFSET(X86_FEATURE_LM) + sym_esi(boot_cpu_data)

        /* Check for availability of long mode. */
        bt      $cpufeat_bit(X86_FEATURE_LM),%edx
        jnc     .Lbad_cpu

        /*
         * Check for NX
         *   - If Xen was compiled requiring it simply assert it's
         *     supported. The trampoline already has the right constant.
         *   - Otherwise, update the trampoline EFER mask accordingly.
         */
        bt      $cpufeat_bit(X86_FEATURE_NX), %edx
        jc     .Lgot_nx

        /*
         * NX appears to be unsupported, but it might be hidden.
         *
         * The feature is part of the AMD64 spec, but the very first Intel
         * 64bit CPUs lacked the feature, and thereafter there was a
         * firmware knob to disable the feature. Undo the disable if
         * possible.
         *
         * All 64bit Intel CPUs support this MSR. If virtualised, expect
         * the hypervisor to either emulate the MSR or give us NX.
         */
        xor     %eax, %eax
        cpuid
        cmp     $X86_VENDOR_INTEL_EBX, %ebx
        jnz     .Lno_nx
        cmp     $X86_VENDOR_INTEL_EDX, %edx
        jnz     .Lno_nx
        cmp     $X86_VENDOR_INTEL_ECX, %ecx
        jnz     .Lno_nx

        /* Clear the XD_DISABLE bit */
        mov     $MSR_IA32_MISC_ENABLE, %ecx
        rdmsr
        btr     $2, %edx
        jnc     .Lno_nx
        wrmsr
        orb     $MSR_IA32_MISC_ENABLE_XD_DISABLE >> 32, 4 + sym_esi(trampoline_misc_enable_off)

        /* Check again for NX */
        mov     $0x80000001, %eax
        cpuid
        bt      $cpufeat_bit(X86_FEATURE_NX), %edx
        jnc     .Lno_nx

.Lgot_nx:
#ifndef CONFIG_REQUIRE_NX
        /* Adjust EFER given that NX is present */
        orb     $EFER_NXE >> 8, 1 + sym_esi(trampoline_efer)
.Lno_nx:
#endif

        /* Stash TSC to calculate a good approximation of time-since-boot */
        rdtsc
        mov     %eax,     sym_esi(boot_tsc_stamp)
        mov     %edx, 4 + sym_esi(boot_tsc_stamp)

        /* Relocate pagetables to point at Xen's current location in memory. */
        mov     $_PAGE_PRESENT, %edx
        lea     sym_esi(__page_tables_start), %eax
        lea     sym_esi(__page_tables_end), %edi

1:      test    %edx, (%eax) /* if page present */
        jz      2f
        add     %esi, (%eax) /* pte += base */
2:      add     $8, %eax

        cmp     %edi, %eax
        jb      1b

        .if !IS_ALIGNED(sym_offs(0), 1 << L2_PAGETABLE_SHIFT)
        .error "Symbol offset calculation breaks alignment"
        .endif

        /* Check that the image base is aligned. */
        lea     sym_esi(_start), %eax
        test    $(1 << L2_PAGETABLE_SHIFT) - 1, %eax
        jnz     .Lnot_aligned

        /* Map Xen into the higher mappings using 2M superpages. */
        lea     _PAGE_PSE + PAGE_HYPERVISOR_RWX + sym_esi(_start), %eax
        mov     $sym_offs(_start),   %ecx   /* %eax = PTE to write ^      */
        mov     $sym_offs(_end - 1), %edx
        shr     $L2_PAGETABLE_SHIFT, %ecx   /* %ecx = First slot to write */
        shr     $L2_PAGETABLE_SHIFT, %edx   /* %edx = Final slot to write */

1:      mov     %eax, sym_offs(l2_xenmap)(%esi, %ecx, 8)
        add     $1, %ecx
        add     $1 << L2_PAGETABLE_SHIFT, %eax

        cmp     %edx, %ecx
        jbe     1b

        /*
         * Map Xen into the directmap (needed for early-boot pagetable
         * handling/walking), and identity map Xen into bootmap (needed for
         * the transition into long mode), using 2M superpages.
         */
        lea     sym_esi(_start), %ecx
        lea     -1 + sym_esi(_end), %edx
        lea     _PAGE_PSE + PAGE_HYPERVISOR_RWX(%ecx), %eax /* PTE to write. */
        shr     $L2_PAGETABLE_SHIFT, %ecx                   /* First slot to write. */
        shr     $L2_PAGETABLE_SHIFT, %edx                   /* Final slot to write. */

1:      mov     %eax, sym_offs(l2_bootmap)  (%esi, %ecx, 8)
        mov     %eax, sym_offs(l2_directmap)(%esi, %ecx, 8)
        add     $1, %ecx
        add     $1 << L2_PAGETABLE_SHIFT, %eax

        cmp     %edx, %ecx
        jbe     1b

        /* Map 4x l2_bootmap[] into l3_bootmap[0...3] */
        lea     __PAGE_HYPERVISOR + sym_esi(l2_bootmap), %eax
        mov     %eax, 0  + sym_esi(l3_bootmap)
        add     $PAGE_SIZE, %eax
        mov     %eax, 8  + sym_esi(l3_bootmap)
        add     $PAGE_SIZE, %eax
        mov     %eax, 16 + sym_esi(l3_bootmap)
        add     $PAGE_SIZE, %eax
        mov     %eax, 24 + sym_esi(l3_bootmap)

        /* Map l1_bootmap[] into l2_bootmap[0]. */
        lea     __PAGE_HYPERVISOR + sym_esi(l1_bootmap), %eax
        mov     %eax, sym_esi(l2_bootmap)

        /* Map the permanent trampoline page into l1_bootmap[]. */
        mov     sym_esi(trampoline_phys), %ecx
        lea     __PAGE_HYPERVISOR_RX(%ecx), %edx /* %edx = PTE to write  */
        shr     $PAGE_SHIFT, %ecx                /* %ecx = Slot to write */
        mov     %edx, sym_offs(l1_bootmap)(%esi, %ecx, 8)

        /* Apply relocations to bootstrap trampoline. */
        call    reloc_trampoline32

        /* Do not parse command line on EFI platform here. */
        cmpb    $0, sym_esi(efi_platform)
        jnz     1f

        /* Bail if there is no command line to parse. */
        mov     sym_esi(multiboot_ptr), %ebx
        testl   $MBI_CMDLINE,MB_flags(%ebx)
        jz      1f

        lea     sym_esi(early_boot_opts), %edx
        mov     MB_cmdline(%ebx), %eax
        /*      cmdline_parse_early(cmdline/eax, opts/edx) using fastcall. */
        call    cmdline_parse_early

1:
        /* Switch to low-memory stack which lives at the end of trampoline region. */
        mov     sym_esi(trampoline_phys), %edi
        lea     TRAMPOLINE_SIZE(%edi), %esp
        lea     trampoline_boot_cpu_entry-trampoline_start(%edi),%eax
        pushl   $BOOT_CS32
        push    %eax

        /* Copy bootstrap trampoline to low memory, below 1MB. */
        lea     sym_esi(trampoline_start), %esi
        mov     $((trampoline_end - trampoline_start) / 4),%ecx
        rep movsl

        /* Jump into the relocated trampoline. */
        lret

ENTRY(trampoline_start)
#include "trampoline.S"
ENTRY(trampoline_end)

#include "x86_64.S"
