/*
 *  linux/arch/i386/entry.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * entry.S contains the system-call and fault low-level handling routines.
 * This also contains the timer-interrupt handler, as well as all interrupts
 * and faults that can result in a task-switch.
 *
 * Stack layout in 'ret_from_system_call':
 *	 0(%esp) - %ebx
 *	 4(%esp) - %ecx
 *	 8(%esp) - %edx
 *       C(%esp) - %esi
 *	10(%esp) - %edi
 *	14(%esp) - %ebp
 *	18(%esp) - %eax
 *	1C(%esp) - %ds
 *	20(%esp) - %es
 *	24(%esp) - %fs
 *	28(%esp) - %gs
 *	2C(%esp) - orig_eax
 *	30(%esp) - %eip
 *	34(%esp) - %cs
 *	38(%esp) - %eflags
 *	3C(%esp) - %oldesp
 *	40(%esp) - %oldss
 *
 * "current" is in register %ebx during any slow entries.
 */
/* The idea for callbacks from monitor -> guest OS.
 * 
 * First, we require that all callbacks (either via a supplied
 * interrupt-descriptor-table, or via the special event or failsafe callbacks
 * in the shared-info-structure) are to ring 1. This just makes life easier,
 * in that it means we don't have to do messy GDT/LDT lookups to find
 * out which the privilege-level of the return code-selector. That code
 * would just be a hassle to write, and would need to account for running
 * off the end of the GDT/LDT, for example. For all callbacks we check
 * that the provided
 * return CS is not == __HYPERVISOR_{CS,DS}. Apart from that we're safe as
 * don't allow a guest OS to install ring-0 privileges into the GDT/LDT.
 * It's up to the guest OS to ensure all returns via the IDT are to ring 1.
 * If not, we load incorrect SS/ESP values from the TSS (for ring 1 rather
 * than the correct ring) and bad things are bound to ensue -- IRET is
 * likely to fault, and we may end up killing the domain (no harm can
 * come to the hypervisor itself, though).
 *      
 * When doing a callback, we check if the return CS is in ring 0. If so,
 * callback is delayed until next return to ring != 0.
 * If return CS is in ring 1, then we create a callback frame
 * starting at return SS/ESP. The base of the frame does an intra-privilege
 * interrupt-return.
 * If return CS is in ring > 1, we create a callback frame starting
 * at SS/ESP taken from appropriate section of the current TSS. The base
 * of the frame does an inter-privilege interrupt-return.
 * 
 * Note that the "failsafe callback" uses a special stackframe:
 * { return_DS, return_ES, return_FS, return_GS, return_EIP,
 *   return_CS, return_EFLAGS[, return_ESP, return_SS] }
 * That is, original values for DS/ES/FS/GS are placed on stack rather than
 * in DS/ES/FS/GS themselves. Why? It saves us loading them, only to have them
 * saved/restored in guest OS. Furthermore, if we load them we may cause
 * a fault if they are invalid, which is a hassle to deal with. We avoid
 * that problem if we don't load them :-) This property allows us to use
 * the failsafe callback as a fallback: if we ever fault on loading DS/ES/FS/GS
 * on return to ring != 0, we can simply package it up as a return via
 * the failsafe callback, and let the guest OS sort it out (perhaps by
 * killing an application process). Note that we also do this for any
 * faulting IRET -- just let the guest OS handle it via the event
 * callback.
 *
 * We terminate a domain in the following cases:
 *  - creating a callback stack frame (due to bad ring-1 stack).
 *  - faulting IRET on entry to failsafe callback handler.
 * So, each domain must keep its ring-1 %ss/%esp and failsafe callback
 * handler in good order (absolutely no faults allowed!).
 */

#include <xeno/config.h>
#include <xeno/errno.h>
#include <hypervisor-ifs/hypervisor-if.h>
#include <asm/smp.h>

EBX		= 0x00
ECX		= 0x04
EDX		= 0x08
ESI		= 0x0C
EDI		= 0x10
EBP		= 0x14
EAX		= 0x18
DS		= 0x1C
ES		= 0x20
FS              = 0x24
GS              = 0x28
ORIG_EAX	= 0x2C
EIP		= 0x30
CS		= 0x34
EFLAGS		= 0x38
OLDESP		= 0x3C
OLDSS		= 0x40

/* Offsets in task_struct */
PROCESSOR       =  0
STATE           =  4
HYP_EVENTS      =  8
DOMAIN          = 12        
SHARED_INFO     = 16
EVENT_SEL       = 20
EVENT_ADDR      = 24
FAILSAFE_SEL    = 28
FAILSAFE_ADDR   = 32

/* Offsets in shared_info_t */
EVENTS          =  0
EVENTS_MASK     =  4

/* Offsets in guest_trap_bounce */
GTB_ERROR_CODE   =  0
GTB_CR2          =  4
GTB_FLAGS        =  8
GTB_CS           = 10
GTB_EIP          = 12
GTBF_TRAP        =  1
GTBF_TRAP_NOCODE =  2
GTBF_TRAP_CR2    =  4
                        
CF_MASK		= 0x00000001
IF_MASK		= 0x00000200
NT_MASK		= 0x00004000

#define SAVE_ALL_NOSTI \
	cld; \
	pushl %gs; \
	pushl %fs; \
	pushl %es; \
	pushl %ds; \
	pushl %eax; \
	pushl %ebp; \
	pushl %edi; \
	pushl %esi; \
	pushl %edx; \
	pushl %ecx; \
	pushl %ebx; \
	movl $(__HYPERVISOR_DS),%edx; \
	movl %edx,%ds; \
	movl %edx,%es;

#define SAVE_ALL \
	SAVE_ALL_NOSTI \
	sti;

#define RESTORE_ALL	\
	popl %ebx;	\
	popl %ecx;	\
	popl %edx;	\
	popl %esi;	\
	popl %edi;	\
	popl %ebp;	\
	popl %eax;	\
1:	popl %ds;	\
2:	popl %es;	\
3:	popl %fs;	\
4:	popl %gs;	\
        addl $4,%esp;	\
5:      iret;		\
.section .fixup,"ax";	\
10:     subl $4,%esp;   \
        pushl %gs;      \
9:      pushl %fs;      \
8:      pushl %es;      \
7:      pushl %ds;      \
6:      pushl %eax;     \
	pushl %ebp;     \
	pushl %edi;     \
	pushl %esi;     \
	pushl %edx;     \
	pushl %ecx;     \
	pushl %ebx;     \
	pushl %ss;           \
	popl  %ds;           \
	pushl %ss;           \
	popl  %es;           \
	jmp  failsafe_callback;      \
.previous;                           \
.section __ex_table,"a";             \
	.align 4;	             \
	.long 1b,6b;       	     \
	.long 2b,7b;	             \
	.long 3b,8b;	             \
	.long 4b,9b;	             \
	.long 5b,10b;	             \
.previous

#define GET_CURRENT(reg)   \
	movl $4096-4, reg; \
        orl  %esp, reg;    \
        movl (reg),reg     \

ENTRY(continue_nonidle_task)
	GET_CURRENT(%ebx)
	jmp test_all_events

        ALIGN
/*
 * HYPERVISOR_multicall(call_list, nr_calls)
 *   Execute a list of 'nr_calls' system calls, pointed at by 'call_list'.
 *   This is fairly easy except that:
 *   1. We may fault reading the call list, and must patch that up; and
 *   2. We cannot recursively call HYPERVISOR_multicall, or a malicious
 *      caller could cause our stack to blow up.
 */
do_multicall:
        popl  %eax
        cmpl  $SYMBOL_NAME(multicall_return_from_call),%eax
        je    multicall_return_from_call
        pushl %ebx
        movl  4(%esp),%ebx   /* EBX == call_list */
        movl  8(%esp),%ecx   /* ECX == nr_calls  */
multicall_loop:
        pushl %ecx
multicall_fault1: 
        pushl 20(%ebx)
multicall_fault2: 
        pushl 16(%ebx)
multicall_fault3: 
        pushl 12(%ebx)
multicall_fault4: 
        pushl 8(%ebx)
multicall_fault5: 
        pushl 4(%ebx)
multicall_fault6: 
        movl  (%ebx),%eax
        andl  $255,%eax
        call  *SYMBOL_NAME(hypervisor_call_table)(,%eax,4)
multicall_return_from_call:
        addl  $20,%esp
        popl  %ecx
        addl  $BYTES_PER_MULTICALL_ENTRY,%ebx
        loop  multicall_loop
        popl  %ebx
        xorl  %eax,%eax
        jmp   ret_from_hypervisor_call

.section __ex_table,"a"
        .align 4
        .long multicall_fault1, multicall_fixup1
        .long multicall_fault2, multicall_fixup2
        .long multicall_fault3, multicall_fixup3
        .long multicall_fault4, multicall_fixup4
        .long multicall_fault5, multicall_fixup5
        .long multicall_fault6, multicall_fixup6
.previous
               
.section .fixup,"ax"
multicall_fixup6: 
        addl  $4,%esp
multicall_fixup5: 
        addl  $4,%esp
multicall_fixup4: 
        addl  $4,%esp
multicall_fixup3: 
        addl  $4,%esp
multicall_fixup2: 
        addl  $4,%esp
multicall_fixup1:
        addl  $4,%esp
        popl  %ebx
        movl  $-EFAULT,%eax
        jmp   ret_from_hypervisor_call
.previous        
                
        ALIGN
restore_all:
	RESTORE_ALL

        ALIGN
ENTRY(hypervisor_call)
        pushl %eax			# save orig_eax
	SAVE_ALL
	GET_CURRENT(%ebx)
	andl $255,%eax
	call *SYMBOL_NAME(hypervisor_call_table)(,%eax,4)

ret_from_hypervisor_call:
        movl %eax,EAX(%esp)		# save the return value

test_all_events:
        xorl %ecx,%ecx
        notl %ecx
        cli                             # tests must not race interrupts
/*test_softirqs:*/  
        mov  PROCESSOR(%ebx),%eax
        shl  $6,%eax                    # sizeof(irq_cpustat) == 64
        test %ecx,SYMBOL_NAME(irq_stat)(%eax,1)
        jnz  process_softirqs
/*test_hyp_events:*/
        test %ecx, HYP_EVENTS(%ebx)
        jnz  process_hyp_events
/*test_guest_events:*/
        movl SHARED_INFO(%ebx),%eax
        shl  $31,%ecx                   # %ecx = EVENTS_MASTER_ENABLE_MASK
        test %ecx,EVENTS_MASK(%eax)     
        jz   restore_all                # only notify if master switch enabled
        movl EVENTS(%eax),%ecx
        andl EVENTS_MASK(%eax),%ecx
        jz   restore_all                # skip if no events to deliver
        notl %ecx
        btrl $31,%ecx                   # NB. We clear all events that are
        andl %ecx,EVENTS_MASK(%eax)     # being delivered + master enable.
/*process_guest_events:*/
        mov  PROCESSOR(%ebx),%edx
        shl  $4,%edx                    # sizeof(guest_trap_bounce) == 16
        lea  guest_trap_bounce(%edx),%edx
        movl EVENT_ADDR(%ebx),%eax
        movl %eax,GTB_EIP(%edx)
        movl EVENT_SEL(%ebx),%eax
        movw %ax,GTB_CS(%edx)
        call create_bounce_frame
        jmp  restore_all

        ALIGN
process_softirqs:
        sti       
        call SYMBOL_NAME(do_softirq)
        jmp  test_all_events
        
        ALIGN
process_hyp_events:
        sti
        call SYMBOL_NAME(do_hyp_events)
        jmp  test_all_events

/* No special register assumptions */
failsafe_callback:
        # Check that we are actually returning to ring != 0 because
        # we may fault when returning to another ring 0 activation.
        # This can only occur when restoring FS and GS, which can be avoided
        # by zeroing those registers and trying again. The outermost ring 0
        # activation will do a full failsafe callback to the guest OS.
        # Note that the outermost activation certainly has the "bad" selector
        # value saved away, since interrupts are always disabled in ring 0
        # until all segment registers have been saved.
        movb CS(%esp),%al
        test $3,%al
        jnz  1f
        xorl %eax,%eax
        movl %eax,FS(%esp)
        movl %eax,GS(%esp)
        jmp  restore_all   
1:      GET_CURRENT(%ebx)
        mov  PROCESSOR(%ebx),%eax
        shl  $4,%eax
        lea  guest_trap_bounce(%eax),%edx
        movl FAILSAFE_ADDR(%ebx),%eax
        movl %eax,GTB_EIP(%edx)
        movl FAILSAFE_SEL(%ebx),%eax
        movw %ax,GTB_CS(%edx)
        call create_bounce_frame
        subl $16,%esi                # add DS/ES/FS/GS to failsafe stack frame
        movl DS(%esp),%eax
FAULT1: movl %eax,(%esi) 
        movl ES(%esp),%eax
FAULT2: movl %eax,4(%esi)
        movl FS(%esp),%eax
FAULT3: movl %eax,8(%esi) 
        movl GS(%esp),%eax
FAULT4: movl %eax,12(%esi)
        movl %esi,OLDESP(%esp)
        popl %ebx
        popl %ecx
        popl %edx
        popl %esi
        popl %edi
        popl %ebp
        popl %eax
        addl $20,%esp                # skip DS/ES/FS/GS/ORIG_EAX
FAULT5: iret 

        
/* CREATE A BASIC EXCEPTION FRAME ON GUEST OS (RING-1) STACK:         */
/*   {EIP, CS, EFLAGS, [ESP, SS]}                                     */
/* %edx == guest_trap_bounce, %ebx == task_struct                     */
/* %eax,%ecx are clobbered. %ds:%esi contain new OLDSS/OLDESP.        */
create_bounce_frame:        
        mov  CS+4(%esp),%cl
        test $2,%cl
        jz   1f /* jump if returning to an existing ring-1 activation */
        /* obtain ss/esp from TSS -- no current ring-1 activations */
        movl PROCESSOR(%ebx),%eax
        shll $8,%eax /* multiply by 256 */
        addl $init_tss + 12,%eax
        movl (%eax),%esi /* tss->esp1 */
FAULT6: movl 4(%eax),%ds /* tss->ss1  */
        /* base of stack frame must contain ss/esp (inter-priv iret) */
        subl $8,%esi
        movl OLDESP+4(%esp),%eax
FAULT7: movl %eax,(%esi) 
        movl OLDSS+4(%esp),%eax
FAULT8: movl %eax,4(%esi) 
        jmp 2f
1:      /* obtain ss/esp from oldss/oldesp -- a ring-1 activation exists */
        movl OLDESP+4(%esp),%esi
FAULT9: movl OLDSS+4(%esp),%ds 
2:      /* Construct a stack frame: EFLAGS, CS/EIP */
        subl $12,%esi
        movl EIP+4(%esp),%eax
FAULT10:movl %eax,(%esi) 
        movl CS+4(%esp),%eax
FAULT11:movl %eax,4(%esi) 
        movl EFLAGS+4(%esp),%eax
FAULT12:movl %eax,8(%esi)
        /* Rewrite our stack frame and return to ring 1. */
        /* IA32 Ref. Vol. 3: TF, VM, RF and NT flags are cleared on trap. */
        andl $0xfffcbeff,%eax
        movl %eax,EFLAGS+4(%esp)
        movl %ds,OLDSS+4(%esp)
        movl %esi,OLDESP+4(%esp)
        movzwl %es:GTB_CS(%edx),%eax
        movl %eax,CS+4(%esp)
        movl %es:GTB_EIP(%edx),%eax
        movl %eax,EIP+4(%esp)
        ret
        
                              
.section __ex_table,"a"
        .align 4
        .long FAULT1, kill_domain_fixup3 # Fault writing to ring-1 stack
        .long FAULT2, kill_domain_fixup3 # Fault writing to ring-1 stack
        .long FAULT3, kill_domain_fixup3 # Fault writing to ring-1 stack
        .long FAULT4, kill_domain_fixup3 # Fault writing to ring-1 stack
        .long FAULT5, kill_domain_fixup1 # Fault executing failsafe iret
        .long FAULT6, kill_domain_fixup2 # Fault loading ring-1 stack selector
        .long FAULT7, kill_domain_fixup2 # Fault writing to ring-1 stack
        .long FAULT8, kill_domain_fixup2 # Fault writing to ring-1 stack
        .long FAULT9, kill_domain_fixup2 # Fault loading ring-1 stack selector
        .long FAULT10,kill_domain_fixup2 # Fault writing to ring-1 stack
        .long FAULT11,kill_domain_fixup2 # Fault writing to ring-1 stack
        .long FAULT12,kill_domain_fixup2 # Fault writing to ring-1 stack
        .long FAULT13,kill_domain_fixup3 # Fault writing to ring-1 stack
        .long FAULT14,kill_domain_fixup3 # Fault writing to ring-1 stack
.previous
               
# This handler kills domains which experience unrecoverable faults.
.section .fixup,"ax"
kill_domain_fixup1:
        subl  $4,%esp
        SAVE_ALL
        jmp   kill_domain
kill_domain_fixup2:
        addl  $4,%esp                     
kill_domain_fixup3:
        pushl %ss
        popl  %ds
        jmp   kill_domain
.previous

        ALIGN
process_guest_exception_and_events:        
        mov  PROCESSOR(%ebx),%eax
        shl  $4,%eax
        lea  guest_trap_bounce(%eax),%edx
        testb $~0,GTB_FLAGS(%edx)
        jz   test_all_events
        call create_bounce_frame        # just the basic frame
        mov  %es:GTB_FLAGS(%edx),%cl
        test $GTBF_TRAP_NOCODE,%cl
        jnz  2f
        subl $4,%esi                    # push error_code onto guest frame
        movl %es:GTB_ERROR_CODE(%edx),%eax
FAULT13:movl %eax,(%esi)
        test $GTBF_TRAP_CR2,%cl
        jz   1f
        subl $4,%esi                    # push %cr2 onto guest frame
        movl %es:GTB_CR2(%edx),%eax
FAULT14:movl %eax,(%esi)
1:      movl %esi,OLDESP(%esp)        
2:      push %es                        # unclobber %ds
        pop  %ds 
        movb $0,GTB_FLAGS(%edx)
        jmp  test_all_events

        ALIGN
ENTRY(ret_from_intr)
	GET_CURRENT(%ebx)
        movb CS(%esp),%al
	testb $3,%al	# return to non-supervisor?
	jne test_all_events
	jmp restore_all

        ALIGN
ret_from_exception:
        movb CS(%esp),%al
	testb $3,%al	# return to non-supervisor?
	jne process_guest_exception_and_events
        jmp restore_all

	ALIGN

ENTRY(divide_error)
	pushl $0		# no error code
	pushl $ SYMBOL_NAME(do_divide_error)
	ALIGN
error_code:
	pushl %fs
	pushl %es
	pushl %ds
	pushl %eax
	xorl  %eax,%eax
	pushl %ebp
	pushl %edi
	pushl %esi
	pushl %edx
	decl  %eax			# eax = -1
	pushl %ecx
	pushl %ebx
	cld
	movl  %gs,%ecx
	movl  ORIG_EAX(%esp), %esi	# get the error code
	movl  GS(%esp), %edi		# get the function address
	movl  %eax, ORIG_EAX(%esp)
	movl  %ecx, GS(%esp)
	movl  %esp,%edx
	pushl %esi			# push the error code
	pushl %edx			# push the pt_regs pointer
	movl  $(__HYPERVISOR_DS),%edx
	movl  %edx,%ds
	movl  %edx,%es
	GET_CURRENT(%ebx)
	call  *%edi
        # NB. We reenable interrupts AFTER exception processing, as that is
        #     required by the page fault handler (needs to save %cr2)
        sti
        addl  $8,%esp
	jmp ret_from_exception

ENTRY(coprocessor_error)
	pushl $0
	pushl $ SYMBOL_NAME(do_coprocessor_error)
	jmp error_code

ENTRY(simd_coprocessor_error)
	pushl $0
	pushl $ SYMBOL_NAME(do_simd_coprocessor_error)
	jmp error_code

ENTRY(device_not_available)
	pushl $0
        pushl $SYMBOL_NAME(math_state_restore)
        jmp   error_code

ENTRY(debug)
	pushl $0
	pushl $ SYMBOL_NAME(do_debug)
	jmp error_code

ENTRY(nmi)
	pushl %eax
	SAVE_ALL_NOSTI
	movl %esp,%edx
	pushl $0
	pushl %edx
	call SYMBOL_NAME(do_nmi)
	addl $8,%esp
	RESTORE_ALL

ENTRY(int3)
	pushl $0
	pushl $ SYMBOL_NAME(do_int3)
	jmp error_code

ENTRY(overflow)
	pushl $0
	pushl $ SYMBOL_NAME(do_overflow)
	jmp error_code

ENTRY(bounds)
	pushl $0
	pushl $ SYMBOL_NAME(do_bounds)
	jmp error_code

ENTRY(invalid_op)
	pushl $0
	pushl $ SYMBOL_NAME(do_invalid_op)
	jmp error_code

ENTRY(coprocessor_segment_overrun)
	pushl $0
	pushl $ SYMBOL_NAME(do_coprocessor_segment_overrun)
	jmp error_code

ENTRY(invalid_TSS)
	pushl $ SYMBOL_NAME(do_invalid_TSS)
	jmp error_code

ENTRY(segment_not_present)
	pushl $ SYMBOL_NAME(do_segment_not_present)
	jmp error_code

ENTRY(stack_segment)
	pushl $ SYMBOL_NAME(do_stack_segment)
	jmp error_code

ENTRY(general_protection)
	pushl $ SYMBOL_NAME(do_general_protection)
	jmp error_code

ENTRY(alignment_check)
	pushl $ SYMBOL_NAME(do_alignment_check)
	jmp error_code

ENTRY(page_fault)
	pushl $ SYMBOL_NAME(do_page_fault)
	jmp error_code

ENTRY(machine_check)
	pushl $0
	pushl $ SYMBOL_NAME(do_machine_check)
	jmp error_code

ENTRY(spurious_interrupt_bug)
	pushl $0
	pushl $ SYMBOL_NAME(do_spurious_interrupt_bug)
	jmp error_code

.data
ENTRY(hypervisor_call_table)
        .long SYMBOL_NAME(do_set_trap_table)
        .long SYMBOL_NAME(do_process_page_updates)
        .long SYMBOL_NAME(do_console_write)
        .long SYMBOL_NAME(do_set_gdt)
        .long SYMBOL_NAME(do_stack_switch)
        .long SYMBOL_NAME(do_set_callbacks)
        .long SYMBOL_NAME(do_net_update)
        .long SYMBOL_NAME(do_fpu_taskswitch)
        .long SYMBOL_NAME(do_yield)
        .long SYMBOL_NAME(kill_domain)
        .long SYMBOL_NAME(do_dom0_op)
        .long SYMBOL_NAME(do_network_op)
        .long SYMBOL_NAME(do_block_io_op)
        .long SYMBOL_NAME(do_set_debugreg)
        .long SYMBOL_NAME(do_get_debugreg)
        .long SYMBOL_NAME(do_update_descriptor)
        .long SYMBOL_NAME(do_set_fast_trap)
        .long SYMBOL_NAME(do_dom_mem_op)
        .long SYMBOL_NAME(do_multicall)
        .long SYMBOL_NAME(do_kbd_op)
        .long SYMBOL_NAME(do_update_va_mapping)
        .rept NR_syscalls-((.-hypervisor_call_table)/4)
        .long SYMBOL_NAME(sys_ni_syscall)
	.endr
