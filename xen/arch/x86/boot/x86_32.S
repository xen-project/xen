#include <xen/config.h>
#include <xen/multiboot.h>
#include <public/xen.h>
#include <asm/asm_defns.h>
#include <asm/desc.h>
#include <asm/page.h>
#include <asm/msr.h>

#define  SECONDARY_CPU_FLAG 0xA5A5A5A5
                
        .text

ENTRY(start)
        jmp __start

        .align 4

/*** MULTIBOOT HEADER ****/
#define MULTIBOOT_HEADER_FLAGS (MULTIBOOT_HEADER_MODS_ALIGNED | \
                                MULTIBOOT_HEADER_WANT_MEMORY)
        /* Magic number indicating a Multiboot header. */
        .long MULTIBOOT_HEADER_MAGIC
        /* Flags to bootloader (see Multiboot spec). */
        .long MULTIBOOT_HEADER_FLAGS
        /* Checksum: must be the negated sum of the first two fields. */
        .long -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)
        
not_multiboot_msg:
        .asciz "ERR: Not a Multiboot bootloader!"
not_multiboot:
        mov     $not_multiboot_msg-__PAGE_OFFSET,%esi
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
        
__start:
        /* Set up a few descriptors: on entry only CS is guaranteed good. */
        lgdt    %cs:nopaging_gdt_descr-__PAGE_OFFSET
        mov     $(__HYPERVISOR_DS),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%fs
        mov     %ecx,%gs
        ljmp    $(__HYPERVISOR_CS),$(1f)-__PAGE_OFFSET
1:      lss     stack_start-__PAGE_OFFSET,%esp
        add     $(STACK_SIZE-CPUINFO_sizeof-__PAGE_OFFSET),%esp

        /* Reset EFLAGS (subsumes CLI and CLD). */
        pushl   $0
        popf

        /* Set up FPU. */
        fninit

        /* Set up CR4, except global flag which Intel requires should be     */
        /* left until after paging is enabled (IA32 Manual Vol. 3, Sec. 2.5) */
        mov     mmu_cr4_features-__PAGE_OFFSET,%ecx
        and     $0x7f,%cl   # CR4.PGE (global enable)
        mov     %ecx,%cr4

        cmp     $(SECONDARY_CPU_FLAG),%ebx
        je      start_paging
                
        /* Check for Multiboot bootloader */
        cmp     $0x2BADB002,%eax
        jne     not_multiboot

        /* Initialize BSS (no nasty surprises!) */
        mov     $__bss_start-__PAGE_OFFSET,%edi
        mov     $_end-__PAGE_OFFSET,%ecx
        sub     %edi,%ecx
        xor     %eax,%eax
        rep     stosb

        /* Save the Multiboot info structure for later use. */
        add     $__PAGE_OFFSET,%ebx
        push    %ebx

#ifdef CONFIG_X86_PAE
        /* Initialize low and high mappings of all memory with 2MB pages */
        mov     $idle_pg_table_l2-__PAGE_OFFSET,%edi
        mov     $0xe3,%eax                  /* PRESENT+RW+A+D+2MB */
1:      mov     %eax,__PAGE_OFFSET>>18(%edi) /* high mapping */
        stosl                                /* low mapping */
        add     $4,%edi
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        cmp     $DIRECTMAP_PHYS_END+0xe3,%eax
        jne     1b
1:      stosl   /* low mappings cover as much physmem as possible */
        add     $4,%edi
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        cmp     $HYPERVISOR_VIRT_START+0xe3,%eax
        jne     1b
#else
        /* Initialize low and high mappings of all memory with 4MB pages */
        mov     $idle_pg_table-__PAGE_OFFSET,%edi
        mov     $0xe3,%eax                  /* PRESENT+RW+A+D+4MB */
1:      mov     %eax,__PAGE_OFFSET>>20(%edi) /* high mapping */
        stosl                                /* low mapping */
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        cmp     $DIRECTMAP_PHYS_END+0xe3,%eax
        jne     1b
1:      stosl   /* low mappings cover as much physmem as possible */
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        cmp     $HYPERVISOR_VIRT_START+0xe3,%eax
        jne     1b
#endif
        
        /* Initialise IDT with simple error defaults. */
        lea     ignore_int,%edx
        mov     $(__HYPERVISOR_CS << 16),%eax
        mov     %dx,%ax            /* selector = 0x0010 = cs */
        mov     $0x8E00,%dx        /* interrupt gate - dpl=0, present */
        lea     idt_table-__PAGE_OFFSET,%edi
        mov     $256,%ecx
1:      mov     %eax,(%edi)
        mov     %edx,4(%edi)
        add     $8,%edi
        loop    1b

start_paging:
#ifdef CONFIG_X86_PAE
        /* Enable Execute-Disable (NX/XD) support if it is available. */
        push    %ebx
        mov     $0x80000000,%eax
        cpuid
        cmp     $0x80000000,%eax    /* Any function > 0x80000000? */
        jbe     no_execute_disable
        mov     $0x80000001,%eax
        cpuid
        bt      $20,%edx            /* Execute Disable? */
        jnc     no_execute_disable
        movl    $MSR_EFER,%ecx
        rdmsr
        bts     $_EFER_NX,%eax
        wrmsr
no_execute_disable:
        pop     %ebx
#endif
        mov     $idle_pg_table-__PAGE_OFFSET,%eax
        mov     %eax,%cr3
        mov     $0x80050033,%eax /* hi-to-lo: PG,AM,WP,NE,ET,MP,PE */
        mov     %eax,%cr0
        jmp     1f
1:      /* Install relocated selectors (FS/GS unused). */
        lgdt    gdt_descr
        mov     $(__HYPERVISOR_DS),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%ss
        ljmp    $(__HYPERVISOR_CS),$1f
1:      /* Paging enabled, so we can now enable GLOBAL mappings in CR4. */
        mov     mmu_cr4_features,%ecx
        mov     %ecx,%cr4
        /* Relocate ESP */
        add     $__PAGE_OFFSET,%esp

        lidt    idt_descr
                
        cmp     $(SECONDARY_CPU_FLAG),%ebx
        je      start_secondary

        /* Call into main C routine. This should never return.*/
        call    __start_xen
        ud2     /* Force a panic (invalid opcode). */

/* This is the default interrupt handler. */
int_msg:
        .asciz "Unknown interrupt\n"
        ALIGN
ignore_int:
        cld
        mov     $(__HYPERVISOR_DS),%eax
        mov     %eax,%ds
        mov     %eax,%es
        pushl   $int_msg
        call    printk
1:      jmp     1b

/*** STACK LOCATION ***/
        
ENTRY(stack_start)
        .long cpu0_stack
        .long __HYPERVISOR_DS
        
/*** DESCRIPTOR TABLES ***/

        ALIGN
        
        .word   0    
idt_descr:
        .word   256*8-1
        .long   idt_table

        .word   0
gdt_descr:
        .word   LAST_RESERVED_GDT_BYTE
        .long   gdt_table - FIRST_RESERVED_GDT_BYTE

        .word   0
nopaging_gdt_descr:
        .word   LAST_RESERVED_GDT_BYTE
        .long   gdt_table - FIRST_RESERVED_GDT_BYTE - __PAGE_OFFSET
        
        .align PAGE_SIZE, 0
/* NB. Rings != 0 get access up to MACH2PHYS_VIRT_END. This allows access to */
/*     the machine->physical mapping table. Ring 0 can access all memory.    */
#define GUEST_DESC(d)                                                   \
        .long ((MACH2PHYS_VIRT_END - 1) >> 12) & 0xffff,                \
              ((MACH2PHYS_VIRT_END - 1) >> 12) & (0xf << 16) | (d)
ENTRY(gdt_table)
        .quad 0x0000000000000000     /* unused */
        .quad 0x00cf9a000000ffff     /* 0xe008 ring 0 4.00GB code at 0x0 */
        .quad 0x00cf92000000ffff     /* 0xe010 ring 0 4.00GB data at 0x0 */
        GUEST_DESC(0x00c0ba00)       /* 0xe019 ring 1 3.xxGB code at 0x0 */
        GUEST_DESC(0x00c0b200)       /* 0xe021 ring 1 3.xxGB data at 0x0 */
        GUEST_DESC(0x00c0fa00)       /* 0xe02b ring 3 3.xxGB code at 0x0 */
        GUEST_DESC(0x00c0f200)       /* 0xe033 ring 3 3.xxGB data at 0x0 */
        .quad 0x0000000000000000     /* unused                           */
        .fill 2*NR_CPUS,8,0          /* space for TSS and LDT per CPU    */

        .align PAGE_SIZE, 0

#ifdef CONFIG_X86_PAE
ENTRY(idle_pg_table)
ENTRY(idle_pg_table_l3)
        .long idle_pg_table_l2 + 0*PAGE_SIZE + 0x01 - __PAGE_OFFSET, 0
        .long idle_pg_table_l2 + 1*PAGE_SIZE + 0x01 - __PAGE_OFFSET, 0
        .long idle_pg_table_l2 + 2*PAGE_SIZE + 0x01 - __PAGE_OFFSET, 0
        .long idle_pg_table_l2 + 3*PAGE_SIZE + 0x01 - __PAGE_OFFSET, 0
.section ".bss.page_aligned","w"
ENTRY(idle_pg_table_l2)
        .fill 4*PAGE_SIZE,1,0
#else
.section ".bss.page_aligned","w"
ENTRY(idle_pg_table)
ENTRY(idle_pg_table_l2)
        .fill 1*PAGE_SIZE,1,0
#endif

.section ".bss.stack_aligned","w"
ENTRY(cpu0_stack)
        .fill STACK_SIZE,1,0
