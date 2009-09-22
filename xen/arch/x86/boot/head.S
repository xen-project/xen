#include <xen/config.h>
#include <xen/multiboot.h>
#include <public/xen.h>
#include <asm/asm_defns.h>
#include <asm/desc.h>
#include <asm/page.h>
#include <asm/msr.h>

        .text
        .code32

#undef bootsym_phys
#define sym_phys(sym)     ((sym) - __XEN_VIRT_START)
#define bootsym_phys(sym) ((sym) - trampoline_start + BOOT_TRAMPOLINE)

#define BOOT_CS32        0x0008
#define BOOT_CS64        0x0010
#define BOOT_DS          0x0018
#define BOOT_PSEUDORM_CS 0x0020
#define BOOT_PSEUDORM_DS 0x0028

ENTRY(start)
        jmp     __start

        .align 4
/*** MULTIBOOT HEADER ****/
#define MULTIBOOT_HEADER_FLAGS (MULTIBOOT_HEADER_MODS_ALIGNED | \
                                MULTIBOOT_HEADER_WANT_MEMORY)
        /* Magic number indicating a Multiboot header. */
        .long   MULTIBOOT_HEADER_MAGIC
        /* Flags to bootloader (see Multiboot spec). */
        .long   MULTIBOOT_HEADER_FLAGS
        /* Checksum: must be the negated sum of the first two fields. */
        .long   -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)

        .section .init.text, "ax"

.Lbad_cpu_msg: .asciz "ERR: Not a 64-bit CPU!"
.Lbad_ldr_msg: .asciz "ERR: Not a Multiboot bootloader!"

bad_cpu:
        mov     $(sym_phys(.Lbad_cpu_msg)),%esi # Error message
        jmp     print_err
not_multiboot:
        mov     $(sym_phys(.Lbad_ldr_msg)),%esi # Error message
print_err:
        mov     $0xB8000,%edi  # VGA framebuffer
1:      mov     (%esi),%bl
        test    %bl,%bl        # Terminate on '\0' sentinel
2:      je      2b
        mov     $0x3f8+5,%dx   # UART Line Status Register
3:      in      %dx,%al
        test    $0x20,%al      # Test THR Empty flag
        je      3b
        mov     $0x3f8+0,%dx   # UART Transmit Holding Register
        mov     %bl,%al
        out     %al,%dx        # Send a character over the serial line
        movsb                  # Write a character to the VGA framebuffer
        mov     $7,%al
        stosb                  # Write an attribute to the VGA framebuffer
        jmp     1b

gdt_boot_descr:
        .word   6*8-1
        .long   sym_phys(trampoline_gdt)

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
        cmp     $0x2BADB002,%eax
        jne     not_multiboot

        /* Save the Multiboot info struct (after relocation) for later use. */
        mov     $sym_phys(cpu0_stack)+1024,%esp
        push    %ebx
        call    reloc
        mov     %eax,sym_phys(multiboot_ptr)

        /* Initialize BSS (no nasty surprises!) */
        mov     $sym_phys(__bss_start),%edi
        mov     $sym_phys(_end),%ecx
        sub     %edi,%ecx
        xor     %eax,%eax
        rep     stosb

        /* Interrogate CPU extended features via CPUID. */
        mov     $0x80000000,%eax
        cpuid
        xor     %edx,%edx
        cmp     $0x80000000,%eax    # any function > 0x80000000?
        jbe     1f
        mov     $0x80000001,%eax
        cpuid
1:      mov     %edx,sym_phys(cpuid_ext_features)
        mov     %edx,sym_phys(boot_cpu_data)+CPUINFO_ext_features

#if defined(__x86_64__)
        /* Check for availability of long mode. */
        bt      $29,%edx
        jnc     bad_cpu
        /* Initialise L2 identity-map and xen page table entries (16MB). */
        mov     $sym_phys(l2_identmap),%edi
        mov     $sym_phys(l2_xenmap),%esi
        mov     $0x1e3,%eax                  /* PRESENT+RW+A+D+2MB+GLOBAL */
        mov     $8,%ecx
1:      mov     %eax,(%edi)
        add     $8,%edi
        mov     %eax,(%esi)
        add     $8,%esi
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        loop    1b
        /* Initialise L3 identity-map page directory entries. */
        mov     $sym_phys(l3_identmap),%edi
        mov     $(sym_phys(l2_identmap)+7),%eax
        mov     $4,%ecx
1:      mov     %eax,(%edi)
        add     $8,%edi
        add     $PAGE_SIZE,%eax
        loop    1b
        /* Initialise L3 xen-map page directory entry. */
        mov     $(sym_phys(l2_xenmap)+7),%eax
        mov     %eax,sym_phys(l3_xenmap) + l3_table_offset(XEN_VIRT_START)*8
        /* Hook identity-map and xen-map L3 tables into PML4. */
        mov     $(sym_phys(l3_identmap)+7),%eax
        mov     %eax,sym_phys(idle_pg_table) + (  0*8) /* PML4[  0]: 1:1 map */
        mov     %eax,sym_phys(idle_pg_table) + l4_table_offset(DIRECTMAP_VIRT_START)*8
        mov     $(sym_phys(l3_xenmap)+7),%eax
        mov     %eax,sym_phys(idle_pg_table) + l4_table_offset(XEN_VIRT_START)*8
#else
        /* Initialize low and high mappings of memory with 2MB pages */
        mov     $sym_phys(idle_pg_table_l2),%edi
        mov     $0xe3,%eax                   /* PRESENT+RW+A+D+2MB */
1:      mov     %eax,__PAGE_OFFSET>>18(%edi) /* high mapping */
        stosl                                /* low mapping */
        add     $4,%edi
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        cmp     $DIRECTMAP_PHYS_END+0xe3,%eax
        jne     1b
1:      stosl   /* low mappings cover up to 16MB */
        add     $4,%edi
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        cmp     $(16<<20)+0xe3,%eax
        jne     1b
#endif

        /* Initialize 4kB mappings of first 2MB or 4MB of memory. */
        mov     $sym_phys(l1_identmap),%edi
        mov     $0x263,%eax                  /* PRESENT+RW+A+D+SMALL_PAGES */
#if defined(__x86_64__)
        or      $0x100,%eax                  /* GLOBAL */
#endif
        xor     %ecx,%ecx
1:      stosl
        add     $4,%edi
        add     $PAGE_SIZE,%eax
        inc     %ecx
        /* VGA hole (0xa0000-0xc0000) should be mapped UC. */
        cmp     $0xa0,%ecx
        jne     2f
        or      $0x10,%eax                   /* +PCD */
2:      cmp     $0xc0,%ecx
        jne     2f
        and     $~0x10,%eax                  /* -PCD */
2:      cmp     $L1_PAGETABLE_ENTRIES,%ecx
        jne     1b
        sub     $(PAGE_SIZE-0x63),%edi
#if defined(__x86_64__)
        mov     %edi,sym_phys(l2_identmap)
        mov     %edi,sym_phys(l2_xenmap)
#else
        mov     %edi,sym_phys(idle_pg_table_l2)
        mov     %edi,sym_phys(idle_pg_table_l2) + (__PAGE_OFFSET>>18)
#endif

        /* Copy bootstrap trampoline to low memory, below 1MB. */
        mov     $sym_phys(trampoline_start),%esi
        mov     $bootsym_phys(trampoline_start),%edi
        mov     $trampoline_end - trampoline_start,%ecx
        rep     movsb

        mov     $bootsym_phys(early_stack),%esp
        call    cmdline_parse_early

        /* Jump into the relocated trampoline. */
        jmp     $BOOT_CS32,$bootsym_phys(trampoline_boot_cpu_entry)

#include "cmdline.S"

reloc:
#include "reloc.S"

        .align 16
        .globl trampoline_start, trampoline_end
trampoline_start:
#include "trampoline.S"
trampoline_end:

        .text
__high_start:
#ifdef __x86_64__
#include "x86_64.S"
#else
#include "x86_32.S"
#endif
