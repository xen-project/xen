/*
 * Hypercall and fault low-level handling routines.
 *
 * Copyright (c) 2002-2004, K A Fraser
 * Copyright (c) 1991, 1992 Linus Torvalds
 * 
 * Calling back to a guest OS:
 * ===========================
 * 
 * First, we require that all callbacks (either via a supplied
 * interrupt-descriptor-table, or via the special event or failsafe callbacks
 * in the shared-info-structure) are to ring 1. This just makes life easier,
 * in that it means we don't have to do messy GDT/LDT lookups to find
 * out which the privilege-level of the return code-selector. That code
 * would just be a hassle to write, and would need to account for running
 * off the end of the GDT/LDT, for example. For all callbacks we check
 * that the provided return CS is not == __HYPERVISOR_{CS,DS}. Apart from that 
 * we're safe as don't allow a guest OS to install ring-0 privileges into the
 * GDT/LDT. It's up to the guest OS to ensure all returns via the IDT are to
 * ring 1. If not, we load incorrect SS/ESP values from the TSS (for ring 1
 * rather than the correct ring) and bad things are bound to ensue -- IRET is
 * likely to fault, and we may end up killing the domain (no harm can
 * come to Xen, though).
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

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/softirq.h>
#include <asm/x86_32/asm_defns.h>
#include <public/xen.h>

#define GET_CURRENT(reg)   \
        movl $8192-4, reg; \
        orl  %esp, reg;    \
        andl $~3,reg;      \
        movl (reg),reg;

ENTRY(continue_nonidle_task)
        GET_CURRENT(%ebx)
        jmp test_all_events

        ALIGN
/*
 * HYPERVISOR_multicall(call_list, nr_calls)
 *   Execute a list of 'nr_calls' hypercalls, pointed at by 'call_list'.
 *   This is fairly easy except that:
 *   1. We may fault reading the call list, and must patch that up; and
 *   2. We cannot recursively call HYPERVISOR_multicall, or a malicious
 *      caller could cause our stack to blow up.
 */
#define MULTICALL_ENTRY_ORDER 5
do_multicall:
        popl  %eax
        cmpl  $SYMBOL_NAME(multicall_return_from_call),%eax
        je    multicall_return_from_call
        pushl %ebx
        movl  4(%esp),%ebx   /* EBX == call_list */
        movl  8(%esp),%ecx   /* ECX == nr_calls  */
        /* Ensure the entire multicall list is below HYPERVISOR_VIRT_START. */
        movl  %ecx,%eax
        shll  $MULTICALL_ENTRY_ORDER,%eax
        addl  %ebx,%eax      /* EAX == end of multicall list */
        jc    bad_multicall_address
        cmpl  $__HYPERVISOR_VIRT_START,%eax
        jnc   bad_multicall_address
multicall_loop:
        pushl %ecx
        movl  4(%esp),%ecx               # %ecx = struct domain
        movl  DOMAIN_processor(%ecx),%eax
        shl   $6,%eax                    # sizeof(irq_cpustat) == 64
        testl $~0,SYMBOL_NAME(irq_stat)(%eax,1)
        jnz   multicall_preempt
multicall_fault1: 
        pushl 20(%ebx)      # args[4]
multicall_fault2: 
        pushl 16(%ebx)      # args[3]
multicall_fault3: 
        pushl 12(%ebx)      # args[2]
multicall_fault4: 
        pushl 8(%ebx)       # args[1]
multicall_fault5: 
        pushl 4(%ebx)       # args[0]
multicall_fault6: 
        movl  (%ebx),%eax   # op
        andl  $(NR_hypercalls-1),%eax
        call  *SYMBOL_NAME(hypercall_table)(,%eax,4)
multicall_return_from_call:
multicall_fault7:
        movl  %eax,24(%ebx) # args[5] == result
        addl  $20,%esp
        popl  %ecx
        addl  $(1<<MULTICALL_ENTRY_ORDER),%ebx
        loop  multicall_loop
        popl  %ebx
        xorl  %eax,%eax
        jmp   ret_from_hypercall

multicall_preempt:
        # NB. remaining nr_calls is already at top of stack
        pushl %ebx                             # call_list
        pushl $2                               # nr_args == 2
        pushl $__HYPERVISOR_multicall          # op == __HYPERVISOR_multicall
        call  hypercall_create_continuation
        addl  $16,%esp
        popl  %ebx
        movl  $__HYPERVISOR_multicall,%eax        
        jmp   ret_from_hypercall
        
bad_multicall_address:
        popl  %ebx
        movl  $-EFAULT,%eax
        jmp   ret_from_hypercall        
                
.section __ex_table,"a"
        .align 4
        .long multicall_fault1, multicall_fixup1
        .long multicall_fault2, multicall_fixup2
        .long multicall_fault3, multicall_fixup3
        .long multicall_fault4, multicall_fixup4
        .long multicall_fault5, multicall_fixup5
        .long multicall_fault6, multicall_fixup6
        .long multicall_fault7, multicall_fixup6
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
        jmp   ret_from_hypercall
.previous        
                
        ALIGN
restore_all_guest:
        testb $TF_failsafe_return,DOMAIN_thread_flags(%ebx)
        jnz  failsafe_callback
FLT1:   movl XREGS_ds(%esp),%ds
FLT2:   movl XREGS_es(%esp),%es
FLT3:   movl XREGS_fs(%esp),%fs
FLT4:   movl XREGS_gs(%esp),%gs
        popl %ebx
        popl %ecx
        popl %edx
        popl %esi
        popl %edi
        popl %ebp
        popl %eax
        addl $4,%esp
FLT5:   iret
.section .fixup,"ax"
FIX5:   subl  $28,%esp
        pushl 28(%esp)                 # error_code/entry_vector
        movl  %eax,XREGS_eax+4(%esp)
        movl  %ebp,XREGS_ebp+4(%esp)
        movl  %edi,XREGS_edi+4(%esp)
        movl  %esi,XREGS_esi+4(%esp)
        movl  %edx,XREGS_edx+4(%esp)
        movl  %ecx,XREGS_ecx+4(%esp)
        movl  %ebx,XREGS_ebx+4(%esp)
FIX1:   SET_XEN_SEGMENTS(a)
        movl  %eax,%fs
        movl  %eax,%gs
        sti
        popl  %esi
        pushfl                         # EFLAGS
        movl  $__HYPERVISOR_CS,%eax
        pushl %eax                     # CS
        movl  $DBLFLT1,%eax
        pushl %eax                     # EIP
        pushl %esi                     # error_code/entry_vector
        jmp   error_code
DBLFLT1:GET_CURRENT(%ebx)
        jmp   test_all_events
DBLFIX1:GET_CURRENT(%ebx)
        testb $TF_failsafe_return,DOMAIN_thread_flags(%ebx)
        jnz   domain_crash             # cannot reenter failsafe code
        orb   $TF_failsafe_return,DOMAIN_thread_flags(%ebx)
        jmp   test_all_events          # will return via failsafe code
.previous
.section __pre_ex_table,"a"
	.long FLT1,FIX1
	.long FLT2,FIX1
	.long FLT3,FIX1
	.long FLT4,FIX1
	.long FLT5,FIX5
.previous
.section __ex_table,"a"
        .long DBLFLT1,DBLFIX1
.previous

/* No special register assumptions */
failsafe_callback:
        GET_CURRENT(%ebx)
        andb $~TF_failsafe_return,DOMAIN_thread_flags(%ebx)
        leal DOMAIN_trap_bounce(%ebx),%edx
        movl DOMAIN_failsafe_addr(%ebx),%eax
        movl %eax,TRAPBOUNCE_eip(%edx)
        movl DOMAIN_failsafe_sel(%ebx),%eax
        movw %ax,TRAPBOUNCE_cs(%edx)
        movw $TBF_FAILSAFE,TRAPBOUNCE_flags(%edx)
        call create_bounce_frame
        popl %ebx
        popl %ecx
        popl %edx
        popl %esi
        popl %edi
        popl %ebp
        popl %eax
        addl $4,%esp
FLT6:   iret 
.section .fixup,"ax"
FIX6:   pushl %ebx
        GET_CURRENT(%ebx)
        orb   $TF_failsafe_return,DOMAIN_thread_flags(%ebx)
        pop   %ebx
        jmp   FIX5
.section __pre_ex_table,"a"
	.long FLT6,FIX6
.previous

        ALIGN
restore_all_xen:
	popl %ebx
	popl %ecx
	popl %edx
	popl %esi
	popl %edi
	popl %ebp
	popl %eax
        addl $4,%esp
        iret

        ALIGN
ENTRY(hypercall)
        subl $4,%esp
	SAVE_ALL(b)
        sti
        GET_CURRENT(%ebx)
	andl $(NR_hypercalls-1),%eax
	call *SYMBOL_NAME(hypercall_table)(,%eax,4)

ret_from_hypercall:
        movl %eax,XREGS_eax(%esp)       # save the return value

test_all_events:
        xorl %ecx,%ecx
        notl %ecx
        cli                             # tests must not race interrupts
/*test_softirqs:*/  
        movl DOMAIN_processor(%ebx),%eax
        shl  $6,%eax                    # sizeof(irq_cpustat) == 64
        test %ecx,SYMBOL_NAME(irq_stat)(%eax,1)
        jnz  process_softirqs
/*test_guest_events:*/
        movl DOMAIN_shared_info(%ebx),%eax
        testb $0xFF,SHINFO_upcall_mask(%eax)
        jnz  restore_all_guest
        testb $0xFF,SHINFO_upcall_pending(%eax)
        jz   restore_all_guest
/*process_guest_events:*/
        leal DOMAIN_trap_bounce(%ebx),%edx
        movl DOMAIN_event_addr(%ebx),%eax
        movl %eax,TRAPBOUNCE_eip(%edx)
        movl DOMAIN_event_sel(%ebx),%eax
        movw %ax,TRAPBOUNCE_cs(%edx)
        movw $TBF_INTERRUPT,TRAPBOUNCE_flags(%edx)
        call create_bounce_frame
        movl DOMAIN_shared_info(%ebx),%eax
        movb $1,SHINFO_upcall_mask(%eax) # Upcalls are masked during delivery
        jmp  restore_all_guest

        ALIGN
process_softirqs:
        sti       
        call SYMBOL_NAME(do_softirq)
        jmp  test_all_events
                
/* CREATE A BASIC EXCEPTION FRAME ON GUEST OS (RING-1) STACK:            */
/*   {EIP, CS, EFLAGS, [ESP, SS]}                                        */
/* %edx == trap_bounce, %ebx == task_struct                              */
/* %eax,%ecx are clobbered. %gs:%esi contain new XREGS_ss/XREGS_esp. */
create_bounce_frame:        
        movb XREGS_cs+4(%esp),%cl
        testb $2,%cl
        jz   1f /* jump if returning to an existing ring-1 activation */
        /* obtain ss/esp from TSS -- no current ring-1 activations */
        movl DOMAIN_processor(%ebx),%eax
        /* next 4 lines multiply %eax by 8320, which is sizeof(tss_struct) */
        movl %eax, %ecx
        shll $7, %ecx
        shll $13, %eax
        addl %ecx,%eax
        addl $init_tss + 12,%eax
        movl (%eax),%esi /* tss->esp1 */
FLT7:   movl 4(%eax),%gs /* tss->ss1  */
        /* base of stack frame must contain ss/esp (inter-priv iret) */
        subl $8,%esi
        movl XREGS_esp+4(%esp),%eax
FLT8:   movl %eax,%gs:(%esi) 
        movl XREGS_ss+4(%esp),%eax
FLT9:   movl %eax,%gs:4(%esi) 
        jmp 2f
1:      /* obtain ss/esp from oldss/oldesp -- a ring-1 activation exists */
        movl XREGS_esp+4(%esp),%esi
FLT10:  movl XREGS_ss+4(%esp),%gs 
2:      /* Construct a stack frame: EFLAGS, CS/EIP */
        subl $12,%esi
        movl XREGS_eip+4(%esp),%eax
FLT11:  movl %eax,%gs:(%esi) 
        movl XREGS_cs+4(%esp),%eax
FLT12:  movl %eax,%gs:4(%esi) 
        movl XREGS_eflags+4(%esp),%eax
FLT13:  movl %eax,%gs:8(%esi)
        movb TRAPBOUNCE_flags(%edx),%cl
        test $TBF_EXCEPTION_ERRCODE,%cl
        jz   1f
        subl $4,%esi                    # push error_code onto guest frame
        movl TRAPBOUNCE_error_code(%edx),%eax
FLT14:  movl %eax,%gs:(%esi)
        testb $TBF_EXCEPTION_CR2,%cl
        jz   2f
        subl $4,%esi                    # push %cr2 onto guest frame
        movl TRAPBOUNCE_cr2(%edx),%eax
FLT15:  movl %eax,%gs:(%esi)
1:      testb $TBF_FAILSAFE,%cl
        jz   2f
        subl $16,%esi                # add DS/ES/FS/GS to failsafe stack frame
        movl XREGS_ds+4(%esp),%eax
FLT16:  movl %eax,%gs:(%esi) 
        movl XREGS_es+4(%esp),%eax
FLT17:  movl %eax,%gs:4(%esi)
        movl XREGS_fs+4(%esp),%eax
FLT18:  movl %eax,%gs:8(%esi) 
        movl XREGS_gs+4(%esp),%eax
FLT19:  movl %eax,%gs:12(%esi)
2:      movb $0,TRAPBOUNCE_flags(%edx)
        /* Rewrite our stack frame and return to ring 1. */
        /* IA32 Ref. Vol. 3: TF, VM, RF and NT flags are cleared on trap. */
        andl $0xfffcbeff,XREGS_eflags+4(%esp)
        movl %gs,XREGS_ss+4(%esp)
        movl %esi,XREGS_esp+4(%esp)
        movzwl TRAPBOUNCE_cs(%edx),%eax
        movl %eax,XREGS_cs+4(%esp)
        movl TRAPBOUNCE_eip(%edx),%eax
        movl %eax,XREGS_eip+4(%esp)
        ret
.section .fixup,"ax"
FIX7:   sti
        popl  %esi
        addl  $4,%esp                  # Discard create_b_frame return address
        pushfl                         # EFLAGS
        movl  $__HYPERVISOR_CS,%eax
        pushl %eax                     # CS
        movl  $DBLFLT2,%eax
        pushl %eax                     # EIP
        pushl %esi                     # error_code/entry_vector
        jmp   error_code
DBLFLT2:jmp   process_guest_exception_and_events
.previous
.section __pre_ex_table,"a"
	.long FLT7,FIX7
	.long FLT8,FIX7
	.long FLT9,FIX7
	.long FLT10,FIX7
	.long FLT11,FIX7
	.long FLT12,FIX7
	.long FLT13,FIX7
	.long FLT14,FIX7
	.long FLT15,FIX7
	.long FLT16,FIX7
	.long FLT17,FIX7
	.long FLT18,FIX7
	.long FLT19,FIX7
.previous
.section __ex_table,"a"
        .long DBLFLT2,domain_crash
.previous

        ALIGN
process_guest_exception_and_events:
        leal DOMAIN_trap_bounce(%ebx),%edx
        testb $TBF_EXCEPTION,TRAPBOUNCE_flags(%edx)
        jz   test_all_events
        call create_bounce_frame
        jmp  test_all_events

        ALIGN
ENTRY(ret_from_intr)
	GET_CURRENT(%ebx)
        movb XREGS_cs(%esp),%al
	testb $3,%al	# return to non-supervisor?
	jnz test_all_events
	jmp restore_all_xen

ENTRY(divide_error)
	pushl $TRAP_divide_error<<16
	ALIGN
error_code:
        SAVE_ALL_NOSEGREGS(a)
        SET_XEN_SEGMENTS(a)
        testb $X86_EFLAGS_IF>>8,XREGS_eflags+1(%esp)
        jz    exception_with_ints_disabled
        sti                             # re-enable interrupts
        xorl  %eax,%eax
        movw  XREGS_entry_vector(%esp),%ax
        movl  %esp,%edx
	pushl %edx			# push the xen_regs pointer
	GET_CURRENT(%ebx)
	call  *SYMBOL_NAME(exception_table)(,%eax,4)
        addl  $4,%esp
        movb  XREGS_cs(%esp),%al
	testb $3,%al
	jz    restore_all_xen
        jmp   process_guest_exception_and_events

exception_with_ints_disabled:
        movb  XREGS_cs(%esp),%al
	testb $3,%al                    # interrupts disabled outside Xen?
	jnz   FATAL_exception_with_ints_disabled
        pushl XREGS_eip(%esp)
        call  search_pre_exception_table
        addl  $4,%esp
        testl %eax,%eax                 # no fixup code for faulting EIP?
        jz    FATAL_exception_with_ints_disabled
        movl  %eax,XREGS_eip(%esp)
        movl  %esp,%esi
        subl  $4,%esp
        movl  %esp,%edi
        movl  $XREGS_kernel_sizeof/4,%ecx
        rep;  movsl                     # make room for error_code/entry_vector
        movl  XREGS_error_code(%esp),%eax # error_code/entry_vector
        movl  %eax,XREGS_kernel_sizeof(%esp)
        jmp   restore_all_xen           # return to fixup code

FATAL_exception_with_ints_disabled:
        xorl  %esi,%esi
        movw  XREGS_entry_vector(%esp),%si
        movl  %esp,%edx
	pushl %edx			# push the xen_regs pointer
        pushl %esi                      # push the trapnr (entry vector)
        call  SYMBOL_NAME(fatal_trap)
        ud2
                                        
ENTRY(coprocessor_error)
	pushl $TRAP_copro_error<<16
	jmp error_code

ENTRY(simd_coprocessor_error)
	pushl $TRAP_simd_error<<16
	jmp error_code

ENTRY(device_not_available)
	pushl $TRAP_no_device<<16
        jmp   error_code

ENTRY(debug)
	pushl $TRAP_debug<<16
	jmp error_code

ENTRY(int3)
	pushl $TRAP_int3<<16
	jmp error_code

ENTRY(overflow)
	pushl $TRAP_overflow<<16
	jmp error_code

ENTRY(bounds)
	pushl $TRAP_bounds<<16
	jmp error_code

ENTRY(invalid_op)
	pushl $TRAP_invalid_op<<16
	jmp error_code

ENTRY(coprocessor_segment_overrun)
	pushl $TRAP_copro_seg<<16
	jmp error_code

ENTRY(invalid_TSS)
        movw $TRAP_invalid_tss,2(%esp)
	jmp error_code

ENTRY(segment_not_present)
        movw $TRAP_no_segment,2(%esp)
	jmp error_code

ENTRY(stack_segment)
        movw $TRAP_stack_error,2(%esp)
	jmp error_code

ENTRY(general_protection)
        movw $TRAP_gp_fault,2(%esp)
	jmp error_code

ENTRY(alignment_check)
        movw $TRAP_alignment_check,2(%esp)
	jmp error_code

ENTRY(page_fault)
        movw $TRAP_page_fault,2(%esp)
	jmp error_code

ENTRY(machine_check)
        pushl $TRAP_machine_check<<16
	jmp error_code

ENTRY(spurious_interrupt_bug)
        pushl $TRAP_spurious_int<<16
	jmp error_code

ENTRY(nmi)
        # Save state but do not trash the segment registers!
        # We may otherwise be unable to reload them or copy them to ring 1. 
	pushl %eax
	SAVE_ALL_NOSEGREGS(a)

        # Check for hardware problems.
        inb   $0x61,%al
        testb $0x80,%al
        jne   nmi_parity_err
        testb $0x40,%al
        jne   nmi_io_err
        movl  %eax,%ebx
        
        # Okay, its almost a normal NMI tick. We can only process it if:
        #  A. We are the outermost Xen activation (in which case we have
        #     the selectors safely saved on our stack)
        #  B. DS-GS all contain sane Xen values.
        # In all other cases we bail without touching DS-GS, as we have
        # interrupted an enclosing Xen activation in tricky prologue or
        # epilogue code.
        movb  XREGS_cs(%esp),%al
	testb $3,%al
        jnz   do_watchdog_tick
        movl  XREGS_ds(%esp),%eax
        cmpw  $(__HYPERVISOR_DS),%ax
        jne   restore_all_xen
        movl  XREGS_es(%esp),%eax
        cmpw  $(__HYPERVISOR_DS),%ax
        jne   restore_all_xen
        movl  XREGS_fs(%esp),%eax
        cmpw  $(__HYPERVISOR_DS),%ax
        jne   restore_all_xen
        movl  XREGS_gs(%esp),%eax
        cmpw  $(__HYPERVISOR_DS),%ax
        jne   restore_all_xen

do_watchdog_tick:
        movl  $(__HYPERVISOR_DS),%edx
        movl  %edx,%ds
        movl  %edx,%es
        movl  %esp,%edx
	pushl %ebx   # reason
	pushl %edx   # regs
        call  SYMBOL_NAME(do_nmi)
	addl  $8,%esp
        movb  XREGS_cs(%esp),%al
	testb $3,%al
	jz    restore_all_xen
        GET_CURRENT(%ebx)
        jmp   restore_all_guest

nmi_parity_err:
        # Clear and disable the parity-error line
        andb $0xf,%al
        orb  $0x4,%al
        outb %al,$0x61
        cmpb $'i',%ss:SYMBOL_NAME(opt_nmi) # nmi=ignore
        je   restore_all_xen
        bts  $0,%ss:SYMBOL_NAME(nmi_softirq_reason)
        bts  $NMI_SOFTIRQ,%ss:SYMBOL_NAME(irq_stat)
        cmpb $'d',%ss:SYMBOL_NAME(opt_nmi) # nmi=dom0
        je   restore_all_xen
        movl $(__HYPERVISOR_DS),%edx       # nmi=fatal
        movl %edx,%ds
        movl %edx,%es
        movl %esp,%edx
        push %edx
        call SYMBOL_NAME(mem_parity_error)
        addl $4,%esp
        jmp  ret_from_intr
                
nmi_io_err: 
        # Clear and disable the I/O-error line
        andb $0xf,%al
        orb  $0x8,%al
        outb %al,$0x61
        cmpb $'i',%ss:SYMBOL_NAME(opt_nmi) # nmi=ignore
        je   restore_all_xen
        bts  $1,%ss:SYMBOL_NAME(nmi_softirq_reason)
        bts  $NMI_SOFTIRQ,%ss:SYMBOL_NAME(irq_stat)
        cmpb $'d',%ss:SYMBOL_NAME(opt_nmi) # nmi=dom0
        je   restore_all_xen
        movl $(__HYPERVISOR_DS),%edx       # nmi=fatal
        movl %edx,%ds
        movl %edx,%es
        movl %esp,%edx
        push %edx
        call SYMBOL_NAME(io_check_error)                        
        addl $4,%esp
        jmp  ret_from_intr
             
.data

ENTRY(exception_table)
        .long SYMBOL_NAME(do_divide_error)
        .long SYMBOL_NAME(do_debug)
        .long 0 # nmi
        .long SYMBOL_NAME(do_int3)
        .long SYMBOL_NAME(do_overflow)
        .long SYMBOL_NAME(do_bounds)
        .long SYMBOL_NAME(do_invalid_op)
        .long SYMBOL_NAME(math_state_restore)
        .long 0 # double fault
        .long SYMBOL_NAME(do_coprocessor_segment_overrun)
        .long SYMBOL_NAME(do_invalid_TSS)
        .long SYMBOL_NAME(do_segment_not_present)
        .long SYMBOL_NAME(do_stack_segment)
        .long SYMBOL_NAME(do_general_protection)
        .long SYMBOL_NAME(do_page_fault)
        .long SYMBOL_NAME(do_spurious_interrupt_bug)
        .long SYMBOL_NAME(do_coprocessor_error)
        .long SYMBOL_NAME(do_alignment_check)
        .long SYMBOL_NAME(do_machine_check)
        .long SYMBOL_NAME(do_simd_coprocessor_error)

ENTRY(hypercall_table)
        .long SYMBOL_NAME(do_set_trap_table)     /*  0 */
        .long SYMBOL_NAME(do_mmu_update)
        .long SYMBOL_NAME(do_set_gdt)
        .long SYMBOL_NAME(do_stack_switch)
        .long SYMBOL_NAME(do_set_callbacks)
        .long SYMBOL_NAME(do_fpu_taskswitch)     /*  5 */
        .long SYMBOL_NAME(do_sched_op)
        .long SYMBOL_NAME(do_dom0_op)
        .long SYMBOL_NAME(do_set_debugreg)
        .long SYMBOL_NAME(do_get_debugreg)
        .long SYMBOL_NAME(do_update_descriptor)  /* 10 */
        .long SYMBOL_NAME(do_set_fast_trap)
        .long SYMBOL_NAME(do_dom_mem_op)
        .long SYMBOL_NAME(do_multicall)
        .long SYMBOL_NAME(do_update_va_mapping)
        .long SYMBOL_NAME(do_set_timer_op)       /* 15 */
        .long SYMBOL_NAME(do_event_channel_op)
        .long SYMBOL_NAME(do_xen_version)
        .long SYMBOL_NAME(do_console_io)
        .long SYMBOL_NAME(do_physdev_op)
        .long SYMBOL_NAME(do_grant_table_op)     /* 20 */
        .long SYMBOL_NAME(do_vm_assist)
        .long SYMBOL_NAME(do_update_va_mapping_otherdomain)
        .rept NR_hypercalls-((.-hypercall_table)/4)
        .long SYMBOL_NAME(do_ni_hypercall)
        .endr
