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
#include <asm/asm_defns.h>
#include <asm/apicdef.h>
#include <public/xen.h>

#define GET_CURRENT(reg)   \
        movl $8192-4, reg; \
        orl  %esp, reg;    \
        andl $~3,reg;      \
        movl (reg),reg;

#ifdef CONFIG_VMX
/*
 * At VMExit time the processor saves the guest selectors, esp, eip, 
 * and eflags. Therefore we don't save them, but simply decrement 
 * the kernel stack pointer to make it consistent with the stack frame 
 * at usual interruption time. The eflags of the host is not saved by VMX, 
 * and we set it to the fixed value.
 *
 * We also need the room, especially because orig_eax field is used 
 * by do_IRQ(). Compared the xen_regs, we skip pushing for the following:
 *   (10) u32 gs;                 
 *   (9)  u32 fs;
 *   (8)  u32 ds;
 *   (7)  u32 es;
 *               <- get_stack_top() (= HOST_ESP)
 *   (6)  u32 ss;
 *   (5)  u32 esp;
 *   (4)  u32 eflags;
 *   (3)  u32 cs;
 *   (2)  u32 eip;
 * (2/1)  u16 entry_vector;
 * (1/1)  u16 error_code;
 * However, get_stack_top() acturally returns 20 bytes below the real
 * top of the stack to allow space for:
 * domain pointer, DS, ES, FS, GS. Therefore, we effectively skip 6 registers.
 */
#define VMX_MONITOR_EFLAGS	0x202 /* IF on */
#define NR_SKIPPED_REGS	6	/* See the above explanation */
#define VMX_SAVE_ALL_NOSEGREGS \
        pushl $VMX_MONITOR_EFLAGS; \
        popf; \
        subl $(NR_SKIPPED_REGS*4), %esp; \
        pushl %eax; \
        pushl %ebp; \
        pushl %edi; \
        pushl %esi; \
        pushl %edx; \
        pushl %ecx; \
        pushl %ebx;

ENTRY(vmx_asm_vmexit_handler)
        /* selectors are restored/saved by VMX */
        VMX_SAVE_ALL_NOSEGREGS
        call SYMBOL_NAME(vmx_vmexit_handler)
        jmp vmx_asm_do_resume

ENTRY(vmx_asm_do_launch)
        popl %ebx
        popl %ecx
        popl %edx
        popl %esi
        popl %edi
        popl %ebp
        popl %eax
        addl $(NR_SKIPPED_REGS*4), %esp
        /* VMLUANCH */
        .byte 0x0f,0x01,0xc2
        pushf
        call SYMBOL_NAME(vm_launch_fail)
        hlt
        
        ALIGN
        
ENTRY(vmx_asm_do_resume)
vmx_test_all_events:
        GET_CURRENT(%ebx)
/* test_all_events: */
        xorl %ecx,%ecx
        notl %ecx
        cli                             # tests must not race interrupts
/*test_softirqs:*/  
        movl EDOMAIN_processor(%ebx),%eax
        shl  $6,%eax                    # sizeof(irq_cpustat) == 64
        test %ecx,SYMBOL_NAME(irq_stat)(%eax,1)
        jnz  vmx_process_softirqs

vmx_restore_all_guest:
        call SYMBOL_NAME(load_cr2)
        /* 
         * Check if we are going back to VMX-based VM
         * By this time, all the setups in the VMCS must be complete.
         */
        popl %ebx
        popl %ecx
        popl %edx
        popl %esi
        popl %edi
        popl %ebp
        popl %eax
        addl $(NR_SKIPPED_REGS*4), %esp
        /* VMRESUME */
        .byte 0x0f,0x01,0xc3
        pushf
        call SYMBOL_NAME(vm_resume_fail)
        /* Should never reach here */
        hlt

        ALIGN
vmx_process_softirqs:
        sti       
        call SYMBOL_NAME(do_softirq)
        jmp  vmx_test_all_events
#endif
        
ENTRY(continue_nonidle_task)
        GET_CURRENT(%ebx)
        jmp test_all_events

        ALIGN
restore_all_guest:
        testb $TF_failsafe_return,EDOMAIN_thread_flags(%ebx)
        jnz  failsafe_callback
        testl $X86_EFLAGS_VM,XREGS_eflags(%esp)
        jnz  restore_all_vm86
FLT1:   movl XREGS_ds(%esp),%ds
FLT2:   movl XREGS_es(%esp),%es
FLT3:   movl XREGS_fs(%esp),%fs
FLT4:   movl XREGS_gs(%esp),%gs
restore_all_vm86:
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
        testb $TF_failsafe_return,EDOMAIN_thread_flags(%ebx)
        jnz   domain_crash             # cannot reenter failsafe code
        orb   $TF_failsafe_return,EDOMAIN_thread_flags(%ebx)
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
        andb $~TF_failsafe_return,EDOMAIN_thread_flags(%ebx)
        leal EDOMAIN_trap_bounce(%ebx),%edx
        movl EDOMAIN_failsafe_addr(%ebx),%eax
        movl %eax,TRAPBOUNCE_eip(%edx)
        movl EDOMAIN_failsafe_sel(%ebx),%eax
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
        orb   $TF_failsafe_return,EDOMAIN_thread_flags(%ebx)
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
        movl EDOMAIN_processor(%ebx),%eax
        shl  $6,%eax                    # sizeof(irq_cpustat) == 64
        test %ecx,SYMBOL_NAME(irq_stat)(%eax,1)
        jnz  process_softirqs
/*test_guest_events:*/
        movl EDOMAIN_vcpu_info(%ebx),%eax
        testb $0xFF,VCPUINFO_upcall_mask(%eax)
        jnz  restore_all_guest
        testb $0xFF,VCPUINFO_upcall_pending(%eax)
        jz   restore_all_guest
/*process_guest_events:*/
        leal EDOMAIN_trap_bounce(%ebx),%edx
        movl EDOMAIN_event_addr(%ebx),%eax
        movl %eax,TRAPBOUNCE_eip(%edx)
        movl EDOMAIN_event_sel(%ebx),%eax
        movw %ax,TRAPBOUNCE_cs(%edx)
        movw $TBF_INTERRUPT,TRAPBOUNCE_flags(%edx)
        call create_bounce_frame
        movl EDOMAIN_vcpu_info(%ebx),%eax
        movb $1,VCPUINFO_upcall_mask(%eax) # Upcalls are masked during delivery
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
        movl XREGS_eflags+4(%esp),%ecx
        movb XREGS_cs+4(%esp),%cl
        testl $(2|X86_EFLAGS_VM),%ecx
        jz   ring1 /* jump if returning to an existing ring-1 activation */
        /* obtain ss/esp from TSS -- no current ring-1 activations */
        movl EDOMAIN_processor(%ebx),%eax
        /* next 4 lines multiply %eax by 8320, which is sizeof(tss_struct) */
        movl %eax, %ecx
        shll $7, %ecx
        shll $13, %eax
        addl %ecx,%eax
        addl $init_tss + 12,%eax
        movl (%eax),%esi /* tss->esp1 */
FLT7:   movl 4(%eax),%gs /* tss->ss1  */
        testl $X86_EFLAGS_VM,XREGS_eflags+4(%esp)
        jz   nvm86_1
	subl $16,%esi       /* push ES/DS/FS/GS (VM86 stack frame) */
	movl XREGS_es+4(%esp),%eax
FLT8:   movl %eax,%gs:(%esi)
	movl XREGS_ds+4(%esp),%eax
FLT9:   movl %eax,%gs:4(%esi)
	movl XREGS_fs+4(%esp),%eax
FLT10:  movl %eax,%gs:8(%esi)
	movl XREGS_gs+4(%esp),%eax
FLT11:  movl %eax,%gs:12(%esi)
nvm86_1:subl $8,%esi        /* push SS/ESP (inter-priv iret) */
        movl XREGS_esp+4(%esp),%eax
FLT12:  movl %eax,%gs:(%esi) 
        movl XREGS_ss+4(%esp),%eax
FLT13:  movl %eax,%gs:4(%esi) 
        jmp 1f
ring1:  /* obtain ss/esp from oldss/oldesp -- a ring-1 activation exists */
        movl XREGS_esp+4(%esp),%esi
FLT14:  movl XREGS_ss+4(%esp),%gs 
1:      /* Construct a stack frame: EFLAGS, CS/EIP */
        subl $12,%esi
        movl XREGS_eip+4(%esp),%eax
FLT15:  movl %eax,%gs:(%esi) 
        movl XREGS_cs+4(%esp),%eax
FLT16:  movl %eax,%gs:4(%esi) 
        movl XREGS_eflags+4(%esp),%eax
FLT17:  movl %eax,%gs:8(%esi)
        movb TRAPBOUNCE_flags(%edx),%cl
        test $TBF_EXCEPTION_ERRCODE,%cl
        jz   1f
        subl $4,%esi                    # push error_code onto guest frame
        movl TRAPBOUNCE_error_code(%edx),%eax
FLT18:  movl %eax,%gs:(%esi)
        testb $TBF_EXCEPTION_CR2,%cl
        jz   2f
        subl $4,%esi                    # push %cr2 onto guest frame
        movl TRAPBOUNCE_cr2(%edx),%eax
FLT19:  movl %eax,%gs:(%esi)
1:      testb $TBF_FAILSAFE,%cl
        jz   2f
        subl $16,%esi                # add DS/ES/FS/GS to failsafe stack frame
        testl $X86_EFLAGS_VM,XREGS_eflags+4(%esp)
        jz   nvm86_2
        xorl %eax,%eax               # VM86: we write zero selector values
FLT20:  movl %eax,%gs:(%esi) 
FLT21:  movl %eax,%gs:4(%esi)
FLT22:  movl %eax,%gs:8(%esi) 
FLT23:  movl %eax,%gs:12(%esi)
        jmp  2f
nvm86_2:movl XREGS_ds+4(%esp),%eax   # non-VM86: write real selector values
FLT24:  movl %eax,%gs:(%esi) 
        movl XREGS_es+4(%esp),%eax
FLT25:  movl %eax,%gs:4(%esi)
        movl XREGS_fs+4(%esp),%eax
FLT26:  movl %eax,%gs:8(%esi) 
        movl XREGS_gs+4(%esp),%eax
FLT27:  movl %eax,%gs:12(%esi)
2:      movb $0,TRAPBOUNCE_flags(%edx)
        testl $X86_EFLAGS_VM,XREGS_eflags+4(%esp)
        jz   nvm86_3
        xorl %eax,%eax      /* zero DS-GS, just as a real CPU would */
        movl %eax,XREGS_ds+4(%esp)
        movl %eax,XREGS_es+4(%esp)
        movl %eax,XREGS_fs+4(%esp)
        movl %eax,XREGS_gs+4(%esp)
nvm86_3:/* Rewrite our stack frame and return to ring 1. */
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
	.long  FLT7,FIX7 ,  FLT8,FIX7 ,  FLT9,FIX7 , FLT10,FIX7
	.long FLT11,FIX7 , FLT12,FIX7 , FLT13,FIX7 , FLT14,FIX7
	.long FLT15,FIX7 , FLT16,FIX7 , FLT17,FIX7 , FLT18,FIX7
	.long FLT19,FIX7 , FLT20,FIX7 , FLT21,FIX7 , FLT22,FIX7
	.long FLT23,FIX7 , FLT24,FIX7 , FLT25,FIX7 , FLT26,FIX7 , FLT27,FIX7
.previous
.section __ex_table,"a"
        .long DBLFLT2,domain_crash
.previous

        ALIGN
process_guest_exception_and_events:
        leal EDOMAIN_trap_bounce(%ebx),%edx
        testb $TBF_EXCEPTION,TRAPBOUNCE_flags(%edx)
        jz   test_all_events
        cli  # create_bounce_frame needs CLI for pre-exceptions to work
        call create_bounce_frame
        jmp  test_all_events

        ALIGN
ENTRY(ret_from_intr)
        GET_CURRENT(%ebx)
        movl  XREGS_eflags(%esp),%eax
        movb  XREGS_cs(%esp),%al
        testl $(3|X86_EFLAGS_VM),%eax
        jnz   test_all_events
        jmp   restore_all_xen

ENTRY(divide_error)
	pushl $TRAP_divide_error<<16
	ALIGN
error_code:
        SAVE_ALL_NOSEGREGS(a)
        SET_XEN_SEGMENTS(a)
        testb $X86_EFLAGS_IF>>8,XREGS_eflags+1(%esp)
        jz    exception_with_ints_disabled
1:      sti                             # re-enable interrupts
        xorl  %eax,%eax
        movw  XREGS_entry_vector(%esp),%ax
        movl  %esp,%edx
	pushl %edx			# push the xen_regs pointer
	GET_CURRENT(%ebx)
	call  *SYMBOL_NAME(exception_table)(,%eax,4)
        addl  $4,%esp
        movl  XREGS_eflags(%esp),%eax
        movb  XREGS_cs(%esp),%al
        testl $(3|X86_EFLAGS_VM),%eax
	jz    restore_all_xen
        jmp   process_guest_exception_and_events

exception_with_ints_disabled:
        movl  XREGS_eflags(%esp),%eax
        movb  XREGS_cs(%esp),%al
        testl $(3|X86_EFLAGS_VM),%eax   # interrupts disabled outside Xen?
        jnz   1b                        # it really does happen!
                                        #  (e.g., DOM0 X server)
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
        movl  XREGS_eflags(%esp),%eax
        movb  XREGS_cs(%esp),%al
        testl $(3|X86_EFLAGS_VM),%eax
        jnz   do_watchdog_tick
        movl  %ds,%eax
        cmpw  $(__HYPERVISOR_DS),%ax
        jne   defer_nmi
        movl  %es,%eax
        cmpw  $(__HYPERVISOR_DS),%ax
        jne   defer_nmi

do_watchdog_tick:
        movl  $(__HYPERVISOR_DS),%edx
        movl  %edx,%ds
        movl  %edx,%es
        movl  %esp,%edx
	pushl %ebx   # reason
	pushl %edx   # regs
        call  SYMBOL_NAME(do_nmi)
	addl  $8,%esp
        movl  XREGS_eflags(%esp),%eax
        movb  XREGS_cs(%esp),%al
        testl $(3|X86_EFLAGS_VM),%eax
	jz    restore_all_xen
        GET_CURRENT(%ebx)
        jmp   restore_all_guest

defer_nmi:
        movl  $FIXMAP_apic_base,%eax
        # apic_wait_icr_idle()
1:      movl  APIC_ICR(%eax),%ebx
        testl $APIC_ICR_BUSY,%ebx
        jnz   1b
        # __send_IPI_shortcut(APIC_DEST_SELF, TRAP_deferred_nmi)
        movl  $(APIC_DM_FIXED | APIC_DEST_SELF | APIC_DEST_LOGICAL | \
                TRAP_deferred_nmi),APIC_ICR(%eax)
        jmp   restore_all_xen

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


ENTRY(setup_vm86_frame)
        # Copies the entire stack frame forwards by 16 bytes.
        .macro copy_vm86_words count=18
        .if \count
        pushl ((\count-1)*4)(%esp)
        popl  ((\count-1)*4)+16(%esp)
        copy_vm86_words "(\count-1)"
        .endif
        .endm
        copy_vm86_words
        addl $16,%esp
        ret

do_switch_vm86:
        # Discard the return address
        addl $4,%esp

        movl XREGS_eflags(%esp),%edx

        # GS:ESI == Ring-1 stack activation
        movl XREGS_esp(%esp),%esi
VFLT1:  movl XREGS_ss(%esp),%gs

        # ES:EDI == Ring-0 stack activation
        leal XREGS_eip(%esp),%edi

        # Restore the hypercall-number-clobbered EAX on our stack frame
VFLT2:  movl %gs:(%esi),%eax
        movl %eax,XREGS_eax(%esp)
        addl $4,%esi
        	
      	# Copy the VM86 activation from the ring-1 stack to the ring-0 stack
        movl $(XREGS_user_sizeof-XREGS_eip)/4,%ecx
VFLT3:  movl %gs:(%esi),%eax
        stosl
        addl $4,%esi
        loop VFLT3

        # Fix up EFLAGS
        andl $~X86_EFLAGS_IOPL,XREGS_eflags(%esp)
        andl $X86_EFLAGS_IOPL,%edx # Ignore attempts to change EFLAGS.IOPL
        jnz  1f
        orl  $X86_EFLAGS_IF,%edx   # EFLAGS.IOPL=0 => no messing with EFLAGS.IF
1:      orl  $X86_EFLAGS_VM,%edx   # Force EFLAGS.VM
        orl  %edx,XREGS_eflags(%esp)
        
        jmp test_all_events

.section __ex_table,"a"
        .long VFLT1,domain_crash
        .long VFLT2,domain_crash
        .long VFLT3,domain_crash
.previous

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
        .long SYMBOL_NAME(do_switch_vm86)
        .long SYMBOL_NAME(do_boot_vcpu)
        .rept NR_hypercalls-((.-hypercall_table)/4)
        .long SYMBOL_NAME(do_ni_hypercall)
        .endr
