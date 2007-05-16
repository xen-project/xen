#include <xen/config.h>
#include <xen/multiboot.h>
#include <public/xen.h>
#include <asm/asm_defns.h>
#include <asm/desc.h>
#include <asm/page.h>
#include <asm/msr.h>

        .text
        .code32

#define SYM_PHYS(sym)       ((sym) - __XEN_VIRT_START)
#define SYM_TRAMP_PHYS(sym) ((sym) - trampoline_start + BOOT_TRAMPOLINE)

#define TRAMP_CS32 0x0008
#define TRAMP_CS64 0x0010
#define TRAMP_DS   0x0018

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

.Lbad_cpu_msg: .asciz "ERR: Not a 64-bit CPU!"
.Lbad_ldr_msg: .asciz "ERR: Not a Multiboot bootloader!"

bad_cpu:
        mov     $(SYM_PHYS(.Lbad_cpu_msg)),%esi # Error message
        jmp     print_err
not_multiboot:
        mov     $(SYM_PHYS(.Lbad_ldr_msg)),%esi # Error message
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
        .word   4*8-1
        .long   SYM_PHYS(trampoline_gdt)

__start:
        cld
        cli

        /* Initialise GDT and basic data segments. */
        lgdt    %cs:SYM_PHYS(gdt_boot_descr)
        mov     $TRAMP_DS,%ecx
        mov     %ecx,%ds
        mov     %ecx,%es

        /* Check for Multiboot bootloader */
        cmp     $0x2BADB002,%eax
        jne     not_multiboot

        /* Save the Multiboot info structure for later use. */
        mov     %ebx,SYM_PHYS(multiboot_ptr)

        /* Initialize BSS (no nasty surprises!) */
        mov     $SYM_PHYS(__bss_start),%edi
        mov     $SYM_PHYS(_end),%ecx
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
1:      mov     %edx,SYM_PHYS(cpuid_ext_features)

#if defined(__x86_64__)
        /* Check for availability of long mode. */
        bt      $29,%edx
        jnc     bad_cpu
        /* Initialise L2 identity-map and xen page table entries (16MB). */
        mov     $SYM_PHYS(l2_identmap),%edi
        mov     $SYM_PHYS(l2_xenmap),%esi
        mov     $0x1e3,%eax                  /* PRESENT+RW+A+D+2MB+GLOBAL */
        mov     $8,%ecx
1:      mov     %eax,(%edi)
        add     $8,%edi
        mov     %eax,(%esi)
        add     $8,%esi
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        loop    1b
        /* Initialise L3 identity-map page directory entries. */
        mov     $SYM_PHYS(l3_identmap),%edi
        mov     $(SYM_PHYS(l2_identmap)+7),%eax
        mov     $4,%ecx
1:      mov     %eax,(%edi)
        add     $8,%edi
        add     $PAGE_SIZE,%eax
        loop    1b
        /* Initialise L3 xen-map page directory entry. */
        mov     $(SYM_PHYS(l2_xenmap)+7),%eax
        mov     %eax,SYM_PHYS(l3_xenmap) + (50*8)
        /* Hook indentity-map and xen-map L3 tables into PML4. */
        mov     $(SYM_PHYS(l3_identmap)+7),%eax
        mov     %eax,SYM_PHYS(idle_pg_table) + (  0*8) /* PML4[  0]: 1:1 map */
        mov     %eax,SYM_PHYS(idle_pg_table) + (262*8) /* PML4[262]: 1:1 map */
        mov     $(SYM_PHYS(l3_xenmap)+7),%eax
        mov     %eax,SYM_PHYS(idle_pg_table) + (261*8) /* PML4[261]: xen map */
#elif defined(CONFIG_X86_PAE)
        /* Initialize low and high mappings of memory with 2MB pages */
        mov     $SYM_PHYS(idle_pg_table_l2),%edi
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
#else
        /* Initialize low and high mappings of memory with 4MB pages */
        mov     $SYM_PHYS(idle_pg_table),%edi
        mov     $0xe3,%eax                   /* PRESENT+RW+A+D+4MB */
1:      mov     %eax,__PAGE_OFFSET>>20(%edi) /* high mapping */
        stosl                                /* low mapping */
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        cmp     $DIRECTMAP_PHYS_END+0xe3,%eax
        jne     1b
1:      stosl   /* low mappings cover up to 16MB */
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        cmp     $(16<<20)+0xe3,%eax
        jne     1b
#endif

        /* Copy bootstrap trampoline to low memory, below 1MB. */
        mov     $SYM_PHYS(trampoline_start),%esi
        mov     $SYM_TRAMP_PHYS(trampoline_start),%edi
        mov     $trampoline_end - trampoline_start,%ecx
        rep     movsb

        /* EBX == 0 indicates we are the BP (Boot Processor). */
        xor     %ebx,%ebx

        /* Jump into the relocated trampoline. */
        jmp     $TRAMP_CS32,$SYM_TRAMP_PHYS(trampoline_protmode_entry)

        .globl trampoline_start, trampoline_end
trampoline_start:
#include "trampoline.S"
trampoline_end:

__high_start:
#ifdef __x86_64__
#include "x86_64.S"
#else
#include "x86_32.S"
#endif
