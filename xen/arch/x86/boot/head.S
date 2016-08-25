#include <xen/config.h>
#include <xen/multiboot.h>
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

        .section .init.rodata, "a", @progbits
        .align 4

        .word   0
gdt_boot_descr:
        .word   6*8-1
        .long   sym_phys(trampoline_gdt)

.Lbad_cpu_msg: .asciz "ERR: Not a 64-bit CPU!"
.Lbad_ldr_msg: .asciz "ERR: Not a Multiboot bootloader!"

        .section .init.text, "ax", @progbits

bad_cpu:
        mov     $(sym_phys(.Lbad_cpu_msg)),%esi # Error message
        jmp     print_err
not_multiboot:
        mov     $(sym_phys(.Lbad_ldr_msg)),%esi # Error message
print_err:
        mov     $0xB8000,%edi  # VGA framebuffer
1:      mov     (%esi),%bl
        test    %bl,%bl        # Terminate on '\0' sentinel
        je      .Lhalt
        mov     $0x3f8+5,%dx   # UART Line Status Register
2:      in      %dx,%al
        test    $0x20,%al      # Test THR Empty flag
        je      2b
        mov     $0x3f8+0,%dx   # UART Transmit Holding Register
        mov     %bl,%al
        out     %al,%dx        # Send a character over the serial line
        movsb                  # Write a character to the VGA framebuffer
        mov     $7,%al
        stosb                  # Write an attribute to the VGA framebuffer
        jmp     1b
.Lhalt: hlt
        jmp     .Lhalt

__start:
        cld
        cli

        /* Initialise GDT and basic data segments. */
        lgdt    %cs:sym_phys(gdt_boot_descr)
        mov     $BOOT_DS,%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%ss

        /* Check for Multiboot bootloader */
        cmp     $MULTIBOOT_BOOTLOADER_MAGIC,%eax
        jne     not_multiboot

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
        testb   $MBI_MEMLIMITS,(%ebx)
        jz      2f                  /* not available? BDA value will be fine */
        mov     MB_mem_lower(%ebx),%edx
        cmp     $0x100,%edx         /* is the multiboot value too small? */
        jb      2f                  /* if so, do not use it */
        shl     $10-4,%edx
        cmp     %ecx,%edx           /* compare with BDA value */
        cmovb   %edx,%ecx           /* and use the smaller */

2:      /* Reserve 64kb for the trampoline */
        sub     $0x1000,%ecx

        /* From arch/x86/smpboot.c: start_eip had better be page-aligned! */
        xor     %cl, %cl
        shl     $4, %ecx
        mov     %ecx,sym_phys(trampoline_phys)

        /* Save the Multiboot info struct (after relocation) for later use. */
        mov     $sym_phys(cpu0_stack)+1024,%esp
        push    %ecx                /* Boot trampoline address. */
        push    %ebx                /* Multiboot information address. */
        call    reloc
        mov     %eax,sym_phys(multiboot_ptr)

        /* Initialize BSS (no nasty surprises!) */
        mov     $sym_phys(__bss_start),%edi
        mov     $sym_phys(__bss_end),%ecx
        sub     %edi,%ecx
        xor     %eax,%eax
        shr     $2,%ecx
        rep stosl

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

        /*
         * During boot, hook 4kB mappings of first 2MB of memory into L2.
         * This avoids mixing cachability for the legacy VGA region, and is
         * corrected when Xen relocates itself.
         */
        mov     $sym_phys(l1_identmap)+__PAGE_HYPERVISOR,%edi
        mov     %edi,sym_phys(l2_xenmap)

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

        call    cmdline_parse_early

        /* Switch to low-memory stack.  */
        mov     sym_phys(trampoline_phys),%edi
        lea     0x10000(%edi),%esp
        lea     trampoline_boot_cpu_entry-trampoline_start(%edi),%eax
        pushl   $BOOT_CS32
        push    %eax

        /* Copy bootstrap trampoline to low memory, below 1MB. */
        mov     $sym_phys(trampoline_start),%esi
        mov     $((trampoline_end - trampoline_start) / 4),%ecx
        rep movsl

        /* Jump into the relocated trampoline. */
        lret

#include "cmdline.S"

reloc:
#include "reloc.S"

ENTRY(trampoline_start)
#include "trampoline.S"
ENTRY(trampoline_end)

#include "x86_64.S"
