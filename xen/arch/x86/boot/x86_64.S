#include <xen/config.h>
#include <public/xen.h>
#include <asm/page.h>
#include <asm/msr.h>

#define  SECONDARY_CPU_FLAG 0xA5A5A5A5
                
        .text
        .code32
        
ENTRY(start)
        jmp __start
        
        .org    0x004
/*** MULTIBOOT HEADER ****/
        /* Magic number indicating a Multiboot header. */
        .long   0x1BADB002
        /* Flags to bootloader (see Multiboot spec). */
        .long   0x00000002
        /* Checksum: must be the negated sum of the first two fields. */
        .long   -0x1BADB004

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
        lgdt    %cs:0x1001f0
        mov     $(__HYPERVISOR_DS),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es

        /* Check for Multiboot bootloader */
        cmp     $(SECONDARY_CPU_FLAG),%ebx
        je      skip_multiboot_check
        cmp     $0x2BADB002,%eax
        jne     not_multiboot
skip_multiboot_check:
        
        /* Save the Multiboot info structure for later use. */
        mov     %ebx,0x1001e0

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
        
        /* Enable PAE in CR4. */
        mov     $0x20,%ecx # X86_CR4_PAE
        mov     %ecx,%cr4

        /* Load pagetable base register. */
        mov     $0x101000,%eax   /* idle_pg_table */
        mov     %eax,%cr3

        /* Set up EFER (Extended Feature Enable Register). */
        movl    $MSR_EFER, %ecx
        rdmsr
        /* Long Mode, SYSCALL/SYSRET, No-Execute */
        movl    $(EFER_LME|EFER_SCE|EFER_NX),%eax
        wrmsr

        mov     $0x80050033,%eax /* hi-to-lo: PG,AM,WP,NE,ET,MP,PE */
        mov     %eax,%cr0
        jmp     1f

1:      /* Now in compatibility mode. Long-jump into 64-bit mode. */
        ljmp    $(__HYPERVISOR_CS64),$0x100100
        
        .code64
        .org    0x0100

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
        lea     ignore_int(%rip),%rdx
        mov     $(__HYPERVISOR_CS64 << 16),%eax
        mov     %dx,%ax            /* selector = 0x0010 = cs */
        mov     $0x8E00,%dx        /* interrupt gate - dpl=0, present */
        lea     idt_table(%rip),%rdi
        mov     $256,%rcx
1:      mov     %eax,(%rdi)
        mov     %edx,4(%rdi)
        add     $8,%rdi
        loop    1b

        /* Pass off the Multiboot info structure to C land. */
        mov     0x1001e0,%edi
        lea     start(%rip),%rax
        sub     $0x100000,%rax
        add     %rax,%rdi
        call    __start_xen
        ud2     /* Force a panic (invalid opcode). */

/* This is the default interrupt handler. */
int_msg:
        .asciz "Unknown interrupt\n"
ignore_int:
        cld
        lea     int_msg(%rip),%rdi
        call    SYMBOL_NAME(printf)
1:      jmp     1b

        .code32

        .org    0x1e0
                        
/*** DESCRIPTOR TABLES ***/

.globl SYMBOL_NAME(idt)
.globl SYMBOL_NAME(gdt)        

        .org    0x1f0
        .word   (LAST_RESERVED_GDT_ENTRY*8)+7
        .long   0x100200 # gdt_table
        
        .org    0x200
ENTRY(gdt_table)
        .fill FIRST_RESERVED_GDT_ENTRY,8,0
        .quad 0x0000000000000000     /* unused */
        .quad 0x00cf9a000000ffff     /* 0x0808 ring 0 code, compatability */
        .quad 0x00af9a000000ffff     /* 0x0810 ring 0 code, 64-bit mode   */
        .quad 0x00cf92000000ffff     /* 0x0818 ring 0 data                */
        .quad 0x00cffa000000ffff     /* 0x0823 ring 3 code, compatibility */
        .quad 0x00affa000000ffff     /* 0x082b ring 3 code, 64-bit mode   */
        .quad 0x00cff2000000ffff     /* 0x0833 ring 3 data                */
        .quad 0x0000000000000000     /* unused                            */
        .fill 2*NR_CPUS,8,0          /* space for TSS and LDT per CPU     */

        .word   0
gdt_descr:
        .word   (LAST_RESERVED_GDT_ENTRY*8)+7
SYMBOL_NAME(gdt):       
        .quad   SYMBOL_NAME(gdt_table)

        .word   0    
idt_descr:
        .word   256*8-1
SYMBOL_NAME(idt):
        .quad   SYMBOL_NAME(idt_table)

ENTRY(stack_start)
        .quad   SYMBOL_NAME(cpu0_stack) + 8100

high_start:
        .quad   __high_start
                
/* Initial PML4 -- level-4 page table */
        .org 0x1000
ENTRY(idle_pg_table)
ENTRY(idle_pg_table_4)
        .quad 0x0000000000102007 # PML4[0]
        .fill 261,8,0
        .quad 0x0000000000102007 # PML4[262]

/* Initial PDP -- level-3 page table */
        .org 0x2000
ENTRY(idle_pg_table_l3)
        .quad 0x0000000000103007

/* Initial PDE -- level-2 page table. */
        .org 0x3000
ENTRY(idle_pg_table_l2)
        .macro identmap from=0, count=512
        .if \count-1
        identmap "(\from+0)","(\count/2)"
        identmap "(\from+(0x200000*(\count/2)))","(\count/2)"
        .else
        .quad 0x00000000000001e3 + \from
        .endif
        .endm
        identmap /* Too orangey for crows :-) */

        .org 0x4000
ENTRY(cpu0_stack)    # Initial stack is 8kB

        .org 0x6000
ENTRY(stext)
ENTRY(_stext)

.globl switch_to, ret_from_intr, do_iopl
switch_to:
ret_from_intr:
do_iopl: 
.globl copy_from_user, copy_to_user, copy_user_generic, new_thread
copy_from_user: 
copy_to_user:
copy_user_generic:
new_thread:
.globl __get_user_1, __get_user_4, __get_user_8
__get_user_1:
__get_user_4:
__get_user_8:
        
