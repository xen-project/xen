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
#include <asm/page.h>
#include <public/xen.h>

#define GET_GUEST_REGS(reg)                     \
        movl $~(STACK_SIZE-1),reg;              \
        andl %esp,reg;                          \
        orl  $(STACK_SIZE-CPUINFO_sizeof),reg;

#define GET_CURRENT(reg)         \
        movl $STACK_SIZE-4, reg; \
        orl  %esp, reg;          \
        andl $~3,reg;            \
        movl (reg),reg;


        ALIGN
restore_all_guest:
        testl $X86_EFLAGS_VM,UREGS_eflags(%esp)
        jnz  restore_all_vm86
#ifdef CONFIG_X86_SUPERVISOR_MODE_KERNEL
        testl $2,UREGS_cs(%esp)
        jnz   1f
        call  restore_ring0_guest
        jmp   restore_all_vm86
1:
#endif
.Lft1:  mov  UREGS_ds(%esp),%ds
.Lft2:  mov  UREGS_es(%esp),%es
.Lft3:  mov  UREGS_fs(%esp),%fs
.Lft4:  mov  UREGS_gs(%esp),%gs
restore_all_vm86:
        popl %ebx
        popl %ecx
        popl %edx
        popl %esi
        popl %edi
        popl %ebp
        popl %eax
        addl $4,%esp
.Lft5:  iret
.section .fixup,"ax"
.Lfx5:  subl  $28,%esp
        pushl 28(%esp)                 # error_code/entry_vector
        movl  %eax,UREGS_eax+4(%esp)
        movl  %ebp,UREGS_ebp+4(%esp)
        movl  %edi,UREGS_edi+4(%esp)
        movl  %esi,UREGS_esi+4(%esp)
        movl  %edx,UREGS_edx+4(%esp)
        movl  %ecx,UREGS_ecx+4(%esp)
        movl  %ebx,UREGS_ebx+4(%esp)
.Lfx1:  SET_XEN_SEGMENTS(a)
        movl  %eax,%fs
        movl  %eax,%gs
        sti
        popl  %esi
        pushfl                         # EFLAGS
        movl  $__HYPERVISOR_CS,%eax
        pushl %eax                     # CS
        movl  $.Ldf1,%eax
        pushl %eax                     # EIP
        pushl %esi                     # error_code/entry_vector
        jmp   handle_exception
.Ldf1:  GET_CURRENT(%ebx)
        jmp   test_all_events
failsafe_callback:
        GET_CURRENT(%ebx)
        leal  VCPU_trap_bounce(%ebx),%edx
        movl  VCPU_failsafe_addr(%ebx),%eax
        movl  %eax,TRAPBOUNCE_eip(%edx)
        movl  VCPU_failsafe_sel(%ebx),%eax
        movw  %ax,TRAPBOUNCE_cs(%edx)
        movw  $TBF_FAILSAFE,TRAPBOUNCE_flags(%edx)
        bt    $_VGCF_failsafe_disables_events,VCPU_guest_context_flags(%ebx)
        jnc   1f
        orw   $TBF_INTERRUPT,TRAPBOUNCE_flags(%edx)
1:      call  create_bounce_frame
        xorl  %eax,%eax
        movl  %eax,UREGS_ds(%esp)
        movl  %eax,UREGS_es(%esp)
        movl  %eax,UREGS_fs(%esp)
        movl  %eax,UREGS_gs(%esp)
        jmp   test_all_events
.previous
.section __pre_ex_table,"a"
        .long .Lft1,.Lfx1
        .long .Lft2,.Lfx1
        .long .Lft3,.Lfx1
        .long .Lft4,.Lfx1
        .long .Lft5,.Lfx5
.previous
.section __ex_table,"a"
        .long .Ldf1,failsafe_callback
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
        FIXUP_RING0_GUEST_STACK
        SAVE_ALL(b)
        sti
        GET_CURRENT(%ebx)
        cmpl  $NR_hypercalls,%eax
        jae   bad_hypercall
        PERFC_INCR(PERFC_hypercalls, %eax)
#ifndef NDEBUG
        /* Create shadow parameters and corrupt those not used by this call. */
        pushl %eax
        pushl UREGS_eip+4(%esp)
        pushl 28(%esp) # EBP
        pushl 28(%esp) # EDI
        pushl 28(%esp) # ESI
        pushl 28(%esp) # EDX
        pushl 28(%esp) # ECX
        pushl 28(%esp) # EBX
        movzb hypercall_args_table(,%eax,1),%ecx
        leal  (%esp,%ecx,4),%edi
        subl  $6,%ecx
        negl  %ecx
        movl  %eax,%esi
        movl  $0xDEADBEEF,%eax
        rep   stosl
        movl  %esi,%eax
#else
        /* 
         * We need shadow parameters even on non-debug builds. We depend on the
         * original versions not being clobbered (needed to create a hypercall
         * continuation). But that isn't guaranteed by the function-call ABI.
         */ 
        pushl 20(%esp) # EBP
        pushl 20(%esp) # EDI
        pushl 20(%esp) # ESI
        pushl 20(%esp) # EDX
        pushl 20(%esp) # ECX
        pushl 20(%esp) # EBX
#endif
        call *hypercall_table(,%eax,4)
        addl  $24,%esp     # Discard the shadow parameters
#ifndef NDEBUG
        /* Deliberately corrupt real parameter regs used by this hypercall. */
        popl  %ecx         # Shadow EIP
        cmpl  %ecx,UREGS_eip+4(%esp)
        popl  %ecx         # Shadow hypercall index
        jne   skip_clobber # If EIP has changed then don't clobber
        movzb hypercall_args_table(,%ecx,1),%ecx
        movl  %esp,%edi
        movl  %eax,%esi
        movl  $0xDEADBEEF,%eax
        rep   stosl
        movl  %esi,%eax
skip_clobber:
#endif
        movl %eax,UREGS_eax(%esp)       # save the return value

test_all_events:
        xorl %ecx,%ecx
        notl %ecx
        cli                             # tests must not race interrupts
/*test_softirqs:*/  
        movl VCPU_processor(%ebx),%eax
        shl  $IRQSTAT_shift,%eax
        test %ecx,irq_stat(%eax,1)
        jnz  process_softirqs
        btr  $_VCPUF_nmi_pending,VCPU_flags(%ebx)
        jc   process_nmi
test_guest_events:
        movl VCPU_vcpu_info(%ebx),%eax
        testb $0xFF,VCPUINFO_upcall_mask(%eax)
        jnz  restore_all_guest
        testb $0xFF,VCPUINFO_upcall_pending(%eax)
        jz   restore_all_guest
/*process_guest_events:*/
        sti
        leal VCPU_trap_bounce(%ebx),%edx
        movl VCPU_event_addr(%ebx),%eax
        movl %eax,TRAPBOUNCE_eip(%edx)
        movl VCPU_event_sel(%ebx),%eax
        movw %ax,TRAPBOUNCE_cs(%edx)
        movw $TBF_INTERRUPT,TRAPBOUNCE_flags(%edx)
        call create_bounce_frame
        jmp  test_all_events

        ALIGN
process_softirqs:
        sti       
        call do_softirq
        jmp  test_all_events

        ALIGN
process_nmi:
        movl VCPU_nmi_addr(%ebx),%eax
        test %eax,%eax
        jz   test_all_events
        bts  $_VCPUF_nmi_masked,VCPU_flags(%ebx)
        jc   1f
        sti
        leal VCPU_trap_bounce(%ebx),%edx
        movl %eax,TRAPBOUNCE_eip(%edx)
        movw $FLAT_KERNEL_CS,TRAPBOUNCE_cs(%edx)
        movw $TBF_INTERRUPT,TRAPBOUNCE_flags(%edx)
        call create_bounce_frame
        jmp  test_all_events
1:      bts  $_VCPUF_nmi_pending,VCPU_flags(%ebx)
        jmp  test_guest_events

bad_hypercall:
        movl $-ENOSYS,UREGS_eax(%esp)
        jmp  test_all_events

/* CREATE A BASIC EXCEPTION FRAME ON GUEST OS (RING-1) STACK:            */
/*   {EIP, CS, EFLAGS, [ESP, SS]}                                        */
/* %edx == trap_bounce, %ebx == struct vcpu                       */
/* %eax,%ecx are clobbered. %gs:%esi contain new UREGS_ss/UREGS_esp. */
create_bounce_frame:
        movl UREGS_eflags+4(%esp),%ecx
        movb UREGS_cs+4(%esp),%cl
        testl $(2|X86_EFLAGS_VM),%ecx
        jz   ring1 /* jump if returning to an existing ring-1 activation */
        movl VCPU_kernel_sp(%ebx),%esi
.Lft6:  mov  VCPU_kernel_ss(%ebx),%gs
        testl $X86_EFLAGS_VM,UREGS_eflags+4(%esp)
        jz   .Lnvm86_1
        subl $16,%esi       /* push ES/DS/FS/GS (VM86 stack frame) */
        movl UREGS_es+4(%esp),%eax
.Lft7:  movl %eax,%gs:(%esi)
        movl UREGS_ds+4(%esp),%eax
.Lft8:  movl %eax,%gs:4(%esi)
        movl UREGS_fs+4(%esp),%eax
.Lft9:  movl %eax,%gs:8(%esi)
        movl UREGS_gs+4(%esp),%eax
.Lft10: movl %eax,%gs:12(%esi)
.Lnvm86_1:
        subl $8,%esi        /* push SS/ESP (inter-priv iret) */
        movl UREGS_esp+4(%esp),%eax
.Lft11: movl %eax,%gs:(%esi)
        movl UREGS_ss+4(%esp),%eax
.Lft12: movl %eax,%gs:4(%esi)
        jmp 1f
ring1:  /* obtain ss/esp from oldss/oldesp -- a ring-1 activation exists */
        movl UREGS_esp+4(%esp),%esi
.Lft13: mov  UREGS_ss+4(%esp),%gs
1:      /* Construct a stack frame: EFLAGS, CS/EIP */
        movb TRAPBOUNCE_flags(%edx),%cl
        subl $12,%esi
        movl UREGS_eip+4(%esp),%eax
.Lft14: movl %eax,%gs:(%esi)
        movl VCPU_vcpu_info(%ebx),%eax
        pushl VCPUINFO_upcall_mask(%eax)
        testb $TBF_INTERRUPT,%cl
        setnz %ch                        # TBF_INTERRUPT -> set upcall mask
        orb  %ch,VCPUINFO_upcall_mask(%eax)
        popl %eax
        shll $16,%eax                    # Bits 16-23: saved_upcall_mask
        movw UREGS_cs+4(%esp),%ax        # Bits  0-15: CS
#ifdef CONFIG_X86_SUPERVISOR_MODE_KERNEL
        testw $2,%ax
        jnz  .Lft15
        and  $~3,%ax                     # RPL 1 -> RPL 0
#endif
.Lft15: movl %eax,%gs:4(%esi)
        test $0x00FF0000,%eax            # Bits 16-23: saved_upcall_mask
        setz %ch                         # %ch == !saved_upcall_mask
        movl UREGS_eflags+4(%esp),%eax
        andl $~X86_EFLAGS_IF,%eax
        shlb $1,%ch                      # Bit 9 (EFLAGS.IF)
        orb  %ch,%ah                     # Fold EFLAGS.IF into %eax
.Lft16: movl %eax,%gs:8(%esi)
        test $TBF_EXCEPTION_ERRCODE,%cl
        jz   1f
        subl $4,%esi                    # push error_code onto guest frame
        movl TRAPBOUNCE_error_code(%edx),%eax
.Lft17: movl %eax,%gs:(%esi)
1:      testb $TBF_FAILSAFE,%cl
        jz   2f
        subl $16,%esi                # add DS/ES/FS/GS to failsafe stack frame
        testl $X86_EFLAGS_VM,UREGS_eflags+4(%esp)
        jz   .Lnvm86_2
        xorl %eax,%eax               # VM86: we write zero selector values
.Lft18: movl %eax,%gs:(%esi)
.Lft19: movl %eax,%gs:4(%esi)
.Lft20: movl %eax,%gs:8(%esi)
.Lft21: movl %eax,%gs:12(%esi)
        jmp  2f
.Lnvm86_2:
        movl UREGS_ds+4(%esp),%eax   # non-VM86: write real selector values
.Lft22: movl %eax,%gs:(%esi)
        movl UREGS_es+4(%esp),%eax
.Lft23: movl %eax,%gs:4(%esi)
        movl UREGS_fs+4(%esp),%eax
.Lft24: movl %eax,%gs:8(%esi)
        movl UREGS_gs+4(%esp),%eax
.Lft25: movl %eax,%gs:12(%esi)
2:      testl $X86_EFLAGS_VM,UREGS_eflags+4(%esp)
        jz   .Lnvm86_3
        xorl %eax,%eax      /* zero DS-GS, just as a real CPU would */
        movl %eax,UREGS_ds+4(%esp)
        movl %eax,UREGS_es+4(%esp)
        movl %eax,UREGS_fs+4(%esp)
        movl %eax,UREGS_gs+4(%esp)
.Lnvm86_3:
        /* Rewrite our stack frame and return to ring 1. */
        /* IA32 Ref. Vol. 3: TF, VM, RF and NT flags are cleared on trap. */
        andl $~(X86_EFLAGS_VM|X86_EFLAGS_RF|\
                X86_EFLAGS_NT|X86_EFLAGS_TF),UREGS_eflags+4(%esp)
        mov  %gs,UREGS_ss+4(%esp)
        movl %esi,UREGS_esp+4(%esp)
        movzwl TRAPBOUNCE_cs(%edx),%eax
        /* Null selectors (0-3) are not allowed. */
        testl $~3,%eax
        jz   domain_crash_synchronous
        movl %eax,UREGS_cs+4(%esp)
        movl TRAPBOUNCE_eip(%edx),%eax
        movl %eax,UREGS_eip+4(%esp)
        movb $0,TRAPBOUNCE_flags(%edx)
        ret
.section __ex_table,"a"
        .long  .Lft6,domain_crash_synchronous ,  .Lft7,domain_crash_synchronous
        .long  .Lft8,domain_crash_synchronous ,  .Lft9,domain_crash_synchronous
        .long .Lft10,domain_crash_synchronous , .Lft11,domain_crash_synchronous
        .long .Lft12,domain_crash_synchronous , .Lft13,domain_crash_synchronous
        .long .Lft14,domain_crash_synchronous , .Lft15,domain_crash_synchronous
        .long .Lft16,domain_crash_synchronous , .Lft17,domain_crash_synchronous
        .long .Lft18,domain_crash_synchronous , .Lft19,domain_crash_synchronous
        .long .Lft20,domain_crash_synchronous , .Lft21,domain_crash_synchronous
        .long .Lft22,domain_crash_synchronous , .Lft23,domain_crash_synchronous
        .long .Lft24,domain_crash_synchronous , .Lft25,domain_crash_synchronous
.previous

domain_crash_synchronous_string:
        .asciz "domain_crash_sync called from entry.S (%lx)\n"

domain_crash_synchronous:
        pushl $domain_crash_synchronous_string
        call  printk
        jmp   __domain_crash_synchronous

        ALIGN
ENTRY(ret_from_intr)
        GET_CURRENT(%ebx)
        movl  UREGS_eflags(%esp),%eax
        movb  UREGS_cs(%esp),%al
        testl $(3|X86_EFLAGS_VM),%eax
        jnz   test_all_events
        jmp   restore_all_xen

ENTRY(divide_error)
        pushl $TRAP_divide_error<<16
        ALIGN
handle_exception:
        FIXUP_RING0_GUEST_STACK
        SAVE_ALL_NOSEGREGS(a)
        SET_XEN_SEGMENTS(a)
        testb $X86_EFLAGS_IF>>8,UREGS_eflags+1(%esp)
        jz    exception_with_ints_disabled
        sti                             # re-enable interrupts
1:      xorl  %eax,%eax
        movw  UREGS_entry_vector(%esp),%ax
        movl  %esp,%edx
        pushl %edx                      # push the cpu_user_regs pointer
        GET_CURRENT(%ebx)
        PERFC_INCR(PERFC_exceptions, %eax)
        call  *exception_table(,%eax,4)
        addl  $4,%esp
        movl  UREGS_eflags(%esp),%eax
        movb  UREGS_cs(%esp),%al
        testl $(3|X86_EFLAGS_VM),%eax
        jz    restore_all_xen
        leal  VCPU_trap_bounce(%ebx),%edx
        testb $TBF_EXCEPTION,TRAPBOUNCE_flags(%edx)
        jz    test_all_events
        call  create_bounce_frame
        jmp   test_all_events

exception_with_ints_disabled:
        movl  UREGS_eflags(%esp),%eax
        movb  UREGS_cs(%esp),%al
        testl $(3|X86_EFLAGS_VM),%eax   # interrupts disabled outside Xen?
        jnz   FATAL_exception_with_ints_disabled
        pushl %esp
        call  search_pre_exception_table
        addl  $4,%esp
        testl %eax,%eax                 # no fixup code for faulting EIP?
        jz    1b
        movl  %eax,UREGS_eip(%esp)
        movl  %esp,%esi
        subl  $4,%esp
        movl  %esp,%edi
        movl  $UREGS_kernel_sizeof/4,%ecx
        rep;  movsl                     # make room for error_code/entry_vector
        movl  UREGS_error_code(%esp),%eax # error_code/entry_vector
        movl  %eax,UREGS_kernel_sizeof(%esp)
        jmp   restore_all_xen           # return to fixup code

FATAL_exception_with_ints_disabled:
        xorl  %esi,%esi
        movw  UREGS_entry_vector(%esp),%si
        movl  %esp,%edx
        pushl %edx                      # push the cpu_user_regs pointer
        pushl %esi                      # push the trapnr (entry vector)
        call  fatal_trap
        ud2
                                        
ENTRY(coprocessor_error)
        pushl $TRAP_copro_error<<16
        jmp   handle_exception

ENTRY(simd_coprocessor_error)
        pushl $TRAP_simd_error<<16
        jmp   handle_exception

ENTRY(device_not_available)
        pushl $TRAP_no_device<<16
        jmp   handle_exception

ENTRY(debug)
        pushl $TRAP_debug<<16
        jmp   handle_exception

ENTRY(int3)
        pushl $TRAP_int3<<16
        jmp   handle_exception

ENTRY(overflow)
        pushl $TRAP_overflow<<16
        jmp   handle_exception

ENTRY(bounds)
        pushl $TRAP_bounds<<16
        jmp   handle_exception

ENTRY(invalid_op)
        pushl $TRAP_invalid_op<<16
        jmp   handle_exception

ENTRY(coprocessor_segment_overrun)
        pushl $TRAP_copro_seg<<16
        jmp   handle_exception

ENTRY(invalid_TSS)
        movw  $TRAP_invalid_tss,2(%esp)
        jmp   handle_exception

ENTRY(segment_not_present)
        movw  $TRAP_no_segment,2(%esp)
        jmp   handle_exception

ENTRY(stack_segment)
        movw  $TRAP_stack_error,2(%esp)
        jmp   handle_exception

ENTRY(general_protection)
        movw  $TRAP_gp_fault,2(%esp)
        jmp   handle_exception

ENTRY(alignment_check)
        movw  $TRAP_alignment_check,2(%esp)
        jmp   handle_exception

ENTRY(page_fault)
        movw  $TRAP_page_fault,2(%esp)
        jmp   handle_exception

ENTRY(machine_check)
        pushl $TRAP_machine_check<<16
        jmp   handle_exception

ENTRY(spurious_interrupt_bug)
        pushl $TRAP_spurious_int<<16
        jmp   handle_exception

ENTRY(early_page_fault)
        SAVE_ALL_NOSEGREGS(a)
        movl  %esp,%edx
        pushl %edx
        call  do_early_page_fault
        addl  $4,%esp
        jmp   restore_all_xen

ENTRY(nmi)
#ifdef CONFIG_X86_SUPERVISOR_MODE_KERNEL
        # NMI entry protocol is incompatible with guest kernel in ring 0.
        iret
#else
        # Save state but do not trash the segment registers!
        # We may otherwise be unable to reload them or copy them to ring 1. 
        pushl %eax
        SAVE_ALL_NOSEGREGS(a)

        # We can only process the NMI if:
        #  A. We are the outermost Xen activation (in which case we have
        #     the selectors safely saved on our stack)
        #  B. DS and ES contain sane Xen values.
        # In all other cases we bail without touching DS-GS, as we have
        # interrupted an enclosing Xen activation in tricky prologue or
        # epilogue code.
        movl  UREGS_eflags(%esp),%eax
        movb  UREGS_cs(%esp),%al
        testl $(3|X86_EFLAGS_VM),%eax
        jnz   continue_nmi
        movl  %ds,%eax
        cmpw  $(__HYPERVISOR_DS),%ax
        jne   defer_nmi
        movl  %es,%eax
        cmpw  $(__HYPERVISOR_DS),%ax
        jne   defer_nmi

continue_nmi:
        SET_XEN_SEGMENTS(d)
        movl  %esp,%edx
        pushl %edx
        call  do_nmi
        addl  $4,%esp
        jmp   ret_from_intr

defer_nmi:
        movl  $FIXMAP_apic_base,%eax
        # apic_wait_icr_idle()
1:      movl  %ss:APIC_ICR(%eax),%ebx
        testl $APIC_ICR_BUSY,%ebx
        jnz   1b
        # __send_IPI_shortcut(APIC_DEST_SELF, TRAP_deferred_nmi)
        movl  $(APIC_DM_FIXED | APIC_DEST_SELF | APIC_DEST_PHYSICAL | \
                TRAP_deferred_nmi),%ss:APIC_ICR(%eax)
        jmp   restore_all_xen
#endif /* !CONFIG_X86_SUPERVISOR_MODE_KERNEL */

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

.data

ENTRY(exception_table)
        .long do_divide_error
        .long do_debug
        .long 0 # nmi
        .long do_int3
        .long do_overflow
        .long do_bounds
        .long do_invalid_op
        .long math_state_restore
        .long 0 # double fault
        .long do_coprocessor_segment_overrun
        .long do_invalid_TSS
        .long do_segment_not_present
        .long do_stack_segment
        .long do_general_protection
        .long do_page_fault
        .long do_spurious_interrupt_bug
        .long do_coprocessor_error
        .long do_alignment_check
        .long do_machine_check
        .long do_simd_coprocessor_error

ENTRY(hypercall_table)
        .long do_set_trap_table     /*  0 */
        .long do_mmu_update
        .long do_set_gdt
        .long do_stack_switch
        .long do_set_callbacks
        .long do_fpu_taskswitch     /*  5 */
        .long do_sched_op_compat
        .long do_platform_op
        .long do_set_debugreg
        .long do_get_debugreg
        .long do_update_descriptor  /* 10 */
        .long do_ni_hypercall
        .long do_memory_op
        .long do_multicall
        .long do_update_va_mapping
        .long do_set_timer_op       /* 15 */
        .long do_event_channel_op_compat
        .long do_xen_version
        .long do_console_io
        .long do_physdev_op_compat
        .long do_grant_table_op     /* 20 */
        .long do_vm_assist
        .long do_update_va_mapping_otherdomain
        .long do_iret
        .long do_vcpu_op
        .long do_ni_hypercall       /* 25 */
        .long do_mmuext_op
        .long do_acm_op
        .long do_nmi_op
        .long do_sched_op
        .long do_callback_op        /* 30 */
        .long do_xenoprof_op
        .long do_event_channel_op
        .long do_physdev_op
        .long do_hvm_op
        .long do_sysctl             /* 35 */
        .long do_domctl
        .long do_kexec_op
        .rept NR_hypercalls-((.-hypercall_table)/4)
        .long do_ni_hypercall
        .endr

ENTRY(hypercall_args_table)
        .byte 1 /* do_set_trap_table    */  /*  0 */
        .byte 4 /* do_mmu_update        */
        .byte 2 /* do_set_gdt           */
        .byte 2 /* do_stack_switch      */
        .byte 4 /* do_set_callbacks     */
        .byte 1 /* do_fpu_taskswitch    */  /*  5 */
        .byte 2 /* do_sched_op_compat   */
        .byte 1 /* do_platform_op       */
        .byte 2 /* do_set_debugreg      */
        .byte 1 /* do_get_debugreg      */
        .byte 4 /* do_update_descriptor */  /* 10 */
        .byte 0 /* do_ni_hypercall      */
        .byte 2 /* do_memory_op         */
        .byte 2 /* do_multicall         */
        .byte 4 /* do_update_va_mapping */
        .byte 2 /* do_set_timer_op      */  /* 15 */
        .byte 1 /* do_event_channel_op_compat */
        .byte 2 /* do_xen_version       */
        .byte 3 /* do_console_io        */
        .byte 1 /* do_physdev_op_compat */
        .byte 3 /* do_grant_table_op    */  /* 20 */
        .byte 2 /* do_vm_assist         */
        .byte 5 /* do_update_va_mapping_otherdomain */
        .byte 0 /* do_iret              */
        .byte 3 /* do_vcpu_op           */
        .byte 0 /* do_ni_hypercall      */  /* 25 */
        .byte 4 /* do_mmuext_op         */
        .byte 1 /* do_acm_op            */
        .byte 2 /* do_nmi_op            */
        .byte 2 /* do_sched_op          */
        .byte 2 /* do_callback_op       */  /* 30 */
        .byte 2 /* do_xenoprof_op       */
        .byte 2 /* do_event_channel_op  */
        .byte 2 /* do_physdev_op        */
        .byte 2 /* do_hvm_op            */
        .byte 1 /* do_sysctl            */  /* 35 */
        .byte 1 /* do_domctl            */
        .byte 2 /* do_kexec_op          */
        .rept NR_hypercalls-(.-hypercall_args_table)
        .byte 0 /* do_ni_hypercall      */
        .endr
