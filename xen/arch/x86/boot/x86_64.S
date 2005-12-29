#include <xen/config.h>
#include <public/xen.h>
#include <asm/desc.h>
#include <asm/page.h>
#include <asm/msr.h>

#define  SECONDARY_CPU_FLAG 0xA5A5A5A5
                
        .text
        .code32

ENTRY(start)
ENTRY(stext)
ENTRY(_stext)
        jmp __start

        .org    0x004
/*** MULTIBOOT HEADER ****/
        /* Magic number indicating a Multiboot header. */
        .long   0x1BADB002
        /* Flags to bootloader (see Multiboot spec). */
        .long   0x00000003
        /* Checksum: must be the negated sum of the first two fields. */
        .long   -0x1BADB005

        .org    0x010
        .asciz "ERR: Not a 64-bit CPU!"
        .org    0x028
        .asciz "ERR: Not a Multiboot bootloader!"
bad_cpu:
        mov     $0x100010,%esi # Error message
        jmp     print_err
not_multiboot:
        mov     $0x100028,%esi # Error message
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

__start:
        cld
        cli

        /* Set up a few descriptors: on entry only CS is guaranteed good. */
        lgdt    %cs:0x100306        # nopaging_gdt_descr
        mov     $(__HYPERVISOR_DS32),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es

        cmp     $(SECONDARY_CPU_FLAG),%ebx
        je      skip_boot_checks

        /* Check for Multiboot bootloader */
        cmp     $0x2BADB002,%eax
        jne     not_multiboot

        /* Save the Multiboot info structure for later use. */
        mov     %ebx,0x100300       # multiboot_ptr

        /* We begin by interrogating the CPU for the presence of long mode. */
        mov     $0x80000000,%eax
        cpuid
        cmp     $0x80000000,%eax    # any function > 0x80000000?
        jbe     bad_cpu
        mov     $0x80000001,%eax
        cpuid
        bt      $29,%edx            # Long mode feature?
        jnc     bad_cpu
        mov     %edx,0x100310       # cpuid_ext_features
skip_boot_checks:

        /* Set up FPU. */
        fninit
        
        /* Enable PAE in CR4. */
        mov     $0x20,%ecx # X86_CR4_PAE
        mov     %ecx,%cr4

        /* Load pagetable base register. */
        mov     $0x102000,%eax   /* idle_pg_table */
        mov     %eax,%cr3

        /* Set up EFER (Extended Feature Enable Register). */
        movl    $MSR_EFER,%ecx
        rdmsr
        btsl    $_EFER_LME,%eax /* Long Mode      */
        btsl    $_EFER_SCE,%eax /* SYSCALL/SYSRET */
        mov     0x100310,%edi
        btl     $20,%edi        /* CPUID 0x80000001, EDX[20] */
        jnc     1f
        btsl    $_EFER_NX,%eax  /* No-Execute     */
1:      wrmsr

        mov     $0x80050033,%eax /* hi-to-lo: PG,AM,WP,NE,ET,MP,PE */
        mov     %eax,%cr0
        jmp     1f

1:      /* Now in compatibility mode. Long-jump into 64-bit mode. */
        ljmp    $(__HYPERVISOR_CS64),$0x100200
        
        .code64
        .org    0x0200

        /* Install relocated selectors (FS/GS unused). */
        lgdt    gdt_descr(%rip)

        /* Enable full CR4 features. */
        mov     mmu_cr4_features(%rip),%rcx
        mov     %rcx,%cr4

        mov     stack_start(%rip),%rsp
        
        /* Reset EFLAGS (subsumes CLI and CLD). */
        pushq   $0
        popf

        /* Jump to high mappings. */
        mov     high_start(%rip),%rax
        push    %rax
        ret
__high_start:
        
        mov     $(__HYPERVISOR_DS64),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%fs
        mov     %ecx,%gs
        mov     %ecx,%ss

        lidt    idt_descr(%rip)
                
        cmp     $(SECONDARY_CPU_FLAG),%ebx
        je      start_secondary

        /* Initialize BSS (no nasty surprises!) */
        lea     __bss_start(%rip),%rdi
        lea     _end(%rip),%rcx
        sub     %rdi,%rcx
        xor     %rax,%rax
        rep     stosb

        /* Initialise IDT with simple error defaults. */
        leaq    ignore_int(%rip),%rcx
        movl    %ecx,%eax
        andl    $0xFFFF0000,%eax
        orl     $0x00008E00,%eax
        shlq    $32,%rax
        movl    %ecx,%edx
        andl    $0x0000FFFF,%edx
        orl     $(__HYPERVISOR_CS64<<16),%edx
        orq     %rdx,%rax
        shrq    $32,%rcx
        movl    %ecx,%edx
        leaq    idt_table(%rip),%rdi
        movl    $256,%ecx
1:      movq    %rax,(%rdi)
        movq    %rdx,8(%rdi)
        addq    $16,%rdi
        loop    1b

        /* Pass off the Multiboot info structure to C land. */
        mov     multiboot_ptr(%rip),%edi
        lea     start-0x100000(%rip),%rax
        add     %rax,%rdi
        call    __start_xen
        ud2     /* Force a panic (invalid opcode). */

/* This is the default interrupt handler. */
int_msg:
        .asciz "Unknown interrupt\n"
ignore_int:
        cld
        leaq    int_msg(%rip),%rdi
        call    printf
1:      jmp     1b


/*** DESCRIPTOR TABLES ***/

.globl idt
.globl gdt        

        .org    0x300
        .code32

multiboot_ptr:        /* 0x300 */
        .long   0

        .word   0
nopaging_gdt_descr:   /* 0x306 */
        .word   LAST_RESERVED_GDT_BYTE
        .quad   gdt_table - FIRST_RESERVED_GDT_BYTE - __PAGE_OFFSET

cpuid_ext_features:   /* 0x310 */
        .long   0
        
        .word   0
gdt_descr:
        .word   LAST_RESERVED_GDT_BYTE
gdt:
        .quad   gdt_table - FIRST_RESERVED_GDT_BYTE

        .word   0,0,0
idt_descr:
        .word   256*16-1
idt:
        .quad   idt_table

ENTRY(stack_start)
        .quad   cpu0_stack + STACK_SIZE

high_start:
        .quad   __high_start

        .org    0x1000
ENTRY(gdt_table)
        .quad 0x0000000000000000     /* unused */
        .quad 0x00cf9a000000ffff     /* 0xe008 ring 0 code, compatibility */
        .quad 0x00af9a000000ffff     /* 0xe010 ring 0 code, 64-bit mode   */
        .quad 0x00cf92000000ffff     /* 0xe018 ring 0 data                */
        .quad 0x00cffa000000ffff     /* 0xe023 ring 3 code, compatibility */
        .quad 0x00cff2000000ffff     /* 0xe02b ring 3 data                */
        .quad 0x00affa000000ffff     /* 0xe033 ring 3 code, 64-bit mode   */
        .quad 0x0000000000000000     /* unused                            */
        .fill 4*NR_CPUS,8,0          /* space for TSS and LDT per CPU     */

/* Initial PML4 -- level-4 page table. */
        .org 0x2000
ENTRY(idle_pg_table)
ENTRY(idle_pg_table_4)
        .quad idle_pg_table_l3 - __PAGE_OFFSET + 7 # PML4[0]
        .fill 261,8,0
        .quad idle_pg_table_l3 - __PAGE_OFFSET + 7 # PML4[262]

/* Initial PDP -- level-3 page table. */
        .org 0x3000
ENTRY(idle_pg_table_l3)
        .quad idle_pg_table_l2 - __PAGE_OFFSET + 7

/* Initial PDE -- level-2 page table. Maps first 64MB physical memory. */
        .org 0x4000
ENTRY(idle_pg_table_l2)
        .macro identmap from=0, count=32
        .if \count-1
        identmap "(\from+0)","(\count/2)"
        identmap "(\from+(0x200000*(\count/2)))","(\count/2)"
        .else
        .quad 0x00000000000001e3 + \from
        .endif
        .endm
        identmap

        .org 0x4000 + PAGE_SIZE
        .code64

.section ".bss.stack_aligned","w"
ENTRY(cpu0_stack)
        .fill STACK_SIZE,1,0
