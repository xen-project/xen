#include <xen/config.h>
#include <hypervisor-ifs/hypervisor-if.h>
#include <asm/page.h>

#define  SECONDARY_CPU_FLAG 0xA5A5A5A5
                
       	.text
        .code32
        
ENTRY(start)
        jmp __start

        .align	4

/*** MULTIBOOT HEADER ****/
        /* Magic number indicating a Multiboot header. */
	.long	0x1BADB002
	/* Flags to bootloader (see Multiboot spec). */
	.long	0x00000002
	/* Checksum: must be the negated sum of the first two fields. */
	.long	-0x1BADB004
        
bad_cpu_msg:
        .asciz "Bad CPU: does not support 64-bit (long) mode."
bad_cpu:
        mov     $SYMBOL_NAME(bad_cpu_msg)-__PAGE_OFFSET,%esi
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
        ljmp    $(__HYPERVISOR_CS32),$(1f)-__PAGE_OFFSET
1:      lss     stack_start-__PAGE_OFFSET,%esp

        /* Reset EFLAGS (subsumes CLI and CLD). */
	pushl	$0
	popf

        /* We begin by interrogating the CPU for the presence of long mode. */
        mov     $0x80000000,%eax
        cpuid
        cmp     $0x80000000,%eax    # any function > 0x80000000?
        jbe     bad_cpu
        mov     $0x80000001,%eax
        cpuid
        bt      $29,%edx            # Long mode feature?
        jnc     bad_cpu
        
        /* Set up FPU. */
        fninit
        
        /* Set up CR4, except global flag which Intel requires should be     */
        /* left until after paging is enabled (IA32 Manual Vol. 3, Sec. 2.5) */
        mov     mmu_cr4_features-__PAGE_OFFSET,%ecx
        and     $0x7f,%cl   # CR4.PGE (global enable)
        mov     %ecx,%cr4
               
        cmp     $(SECONDARY_CPU_FLAG),%ebx
        je      start_paging

      	add     $__PAGE_OFFSET,%ebx
        push    %ebx /* Multiboot info struct */
        push    %eax /* Multiboot magic value */

        /* Initialize BSS (no nasty surprises!) */
        mov     $__bss_start-__PAGE_OFFSET,%edi
        mov     $_end-__PAGE_OFFSET,%ecx
        sub     %edi,%ecx
        xor     %eax,%eax
        rep     stosb

        /* Initialize low and high mappings of all memory with 4MB pages */
        mov     $idle_pg_table-__PAGE_OFFSET,%edi
        mov     $0x1e3,%eax                  /* PRESENT+RW+A+D+4MB+GLOBAL */
1:      mov     %eax,__PAGE_OFFSET>>20(%edi) /* high mapping */
        stosl                                /* low mapping */
        add     $(1<<L2_PAGETABLE_SHIFT),%eax
        cmp     $DIRECTMAP_PHYS_END+0x1e3,%eax
        jne     1b

        /* Initialise IDT with simple error defaults. */
        lea     ignore_int,%edx
        mov     $(__HYPERVISOR_CS64 << 16),%eax
        mov     %dx,%ax            /* selector = 0x0010 = cs */
        mov     $0x8E00,%dx        /* interrupt gate - dpl=0, present */
        lea     SYMBOL_NAME(idt_table)-__PAGE_OFFSET,%edi
        mov     $256,%ecx
1:      mov     %eax,(%edi)
        mov     %edx,4(%edi)
        add     $8,%edi
        loop    1b

start_paging:
        mov     $idle_pg_table-__PAGE_OFFSET,%eax
        mov     %eax,%cr3
        mov     $0x80050033,%eax /* hi-to-lo: PG,AM,WP,NE,ET,MP,PE */
        mov     %eax,%cr0
        jmp     1f
1:      /* Now in compatibility mode. Long-jump into 64-bit mode. */
        ljmp    $(__HYPERVISOR_CS64),$1f

        .code64
1:      /* Install relocated selectors (FS/GS unused). */
        lgdt    gdt_descr
        mov     $(__HYPERVISOR_DS),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%ss
1:      /* Paging enabled, so we can now enable GLOBAL mappings in CR4. */
        mov     mmu_cr4_features,%rcx
        mov     %rcx,%cr4
        /* Relocate ESP */
        add     $__PAGE_OFFSET,%esp

        lidt    idt_descr
                
        cmp     $(SECONDARY_CPU_FLAG),%ebx
        je      start_secondary

        /* Call into main C routine. This should never return.*/
       	call	cmain
        ud2     /* Force a panic (invalid opcode). */

/* This is the default interrupt handler. */
int_msg:
        .asciz "Unknown interrupt\n"
ignore_int:
        cld
        mov     $(__HYPERVISOR_DS),%eax
        mov     %eax,%ds
        mov     %eax,%es
        pushq   $int_msg
        call    SYMBOL_NAME(printf)
1:      jmp     1b

        .code32
        .align 8
                
/*** STACK LOCATION ***/
        
ENTRY(stack_start)
        .long SYMBOL_NAME(cpu0_stack) + 8100 - __PAGE_OFFSET
        .long __HYPERVISOR_DS
        
/*** DESCRIPTOR TABLES ***/

.globl SYMBOL_NAME(idt)
.globl SYMBOL_NAME(gdt)        

        .word   0    
idt_descr:
	.word	256*8-1
SYMBOL_NAME(idt):
        .long	SYMBOL_NAME(idt_table)

        .word   0
gdt_descr:
	.word	(LAST_RESERVED_GDT_ENTRY*8)+7
SYMBOL_NAME(gdt):       
        .long   SYMBOL_NAME(gdt_table)	/* gdt base */

        .word   0
nopaging_gdt_descr:
        .word   (LAST_RESERVED_GDT_ENTRY*8)+7
        .long   SYMBOL_NAME(gdt_table)-__PAGE_OFFSET
        
        .align 64
ENTRY(gdt_table)
        .fill FIRST_RESERVED_GDT_ENTRY,8,0
        .quad 0x0000000000000000     /* unused */
        .quad 0x00cf9a000000ffff     /* 0x0808 ring 0 code, compatability */
        .quad 0x00af9a000000ffff     /* 0x0810 ring 0 code, 64-bit mode   */
        .quad 0x00cf92000000ffff     /* 0x0818 ring 0 data                */
        .quad 0x00cffa000000ffff     /* 0x0823 ring 3 code, compatibility */
        .quad 0x00affa000000ffff     /* 0x082b ring 3 code, 64-bit mode   */
        .quad 0x00cff2000000ffff     /* 0x0833 ring 3 data                */
        .quad 0x0000000000000000     /* unused                           */
        .fill 2*NR_CPUS,8,0          /* space for TSS and LDT per CPU    */

        .org 0x1000
ENTRY(idle_pg_table) # Initial page directory is 4kB
        .org 0x2000
ENTRY(cpu0_stack)    # Initial stack is 8kB
        .org 0x4000
ENTRY(stext)
ENTRY(_stext)
