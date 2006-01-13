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

#ifdef CONFIG_VMX
/*
 * At VMExit time the processor saves the guest selectors, esp, eip, 
 * and eflags. Therefore we don't save them, but simply decrement 
 * the kernel stack pointer to make it consistent with the stack frame 
 * at usual interruption time. The eflags of the host is not saved by VMX, 
 * and we set it to the fixed value.
 *
 * We also need the room, especially because orig_eax field is used 
 * by do_IRQ(). Compared the cpu_user_regs, we skip pushing for the following:
 *   (10) u32 gs;                 
 *   (9)  u32 fs;
 *   (8)  u32 ds;
 *   (7)  u32 es;
 *               <- get_stack_bottom() (= HOST_ESP)
 *   (6)  u32 ss;
 *   (5)  u32 esp;
 *   (4)  u32 eflags;
 *   (3)  u32 cs;
 *   (2)  u32 eip;
 * (2/1)  u16 entry_vector;
 * (1/1)  u16 error_code;
 * However, get_stack_bottom() actually returns 20 bytes before the real
 * bottom of the stack to allow space for:
 * domain pointer, DS, ES, FS, GS. Therefore, we effectively skip 6 registers.
 */
#define VMX_MONITOR_EFLAGS	0x202 /* IF on */
#define NR_SKIPPED_REGS	6	/* See the above explanation */
#define VMX_SAVE_ALL_NOSEGREGS \
        pushl $VMX_MONITOR_EFLAGS; \
        popf; \
        subl $(NR_SKIPPED_REGS*4), %esp; \
        movl $0, 0xc(%esp); /* eflags==0 identifies cpu_user_regs as VMX guest */ \
        pushl %eax; \
        pushl %ebp; \
        pushl %edi; \
        pushl %esi; \
        pushl %edx; \
        pushl %ecx; \
        pushl %ebx;

#define VMX_RESTORE_ALL_NOSEGREGS   \
        popl %ebx;  \
        popl %ecx;  \
        popl %edx;  \
        popl %esi;  \
        popl %edi;  \
        popl %ebp;  \
        popl %eax;  \
        addl $(NR_SKIPPED_REGS*4), %esp

ENTRY(vmx_asm_vmexit_handler)
        /* selectors are restored/saved by VMX */
        VMX_SAVE_ALL_NOSEGREGS
        call trace_vmexit
        call vmx_vmexit_handler
        jmp vmx_asm_do_resume

.macro vmx_asm_common launch initialized
1:
/* vmx_test_all_events */
        .if \initialized
        GET_CURRENT(%ebx)
/*test_all_events:*/
        xorl %ecx,%ecx
        notl %ecx
        cli                             # tests must not race interrupts
/*test_softirqs:*/  
        movl VCPU_processor(%ebx),%eax
        shl  $IRQSTAT_shift,%eax
        test %ecx,irq_stat(%eax,1)
        jnz 2f

/* vmx_restore_all_guest */
        call vmx_intr_assist
        call load_cr2
        call trace_vmentry
        .endif
        VMX_RESTORE_ALL_NOSEGREGS
        /* 
         * Check if we are going back to VMX-based VM
         * By this time, all the setups in the VMCS must be complete.
         */
        .if \launch
        /* VMLAUNCH */
        .byte 0x0f,0x01,0xc2
        pushf
        call vm_launch_fail
        .else
        /* VMRESUME */
        .byte 0x0f,0x01,0xc3
        pushf
        call vm_resume_fail
        .endif
        /* Should never reach here */
        hlt

        ALIGN
        .if \initialized
2:
/* vmx_process_softirqs */
        sti       
        call do_softirq
        jmp 1b
        ALIGN
        .endif
.endm

ENTRY(vmx_asm_do_launch)
    vmx_asm_common 1 0

ENTRY(vmx_asm_do_resume)
    vmx_asm_common 0 1

ENTRY(vmx_asm_do_relaunch)
    vmx_asm_common 1 1

#endif

        ALIGN
restore_all_guest:
        testl $X86_EFLAGS_VM,UREGS_eflags(%esp)
        jnz  restore_all_vm86
FLT1:   mov  UREGS_ds(%esp),%ds
FLT2:   mov  UREGS_es(%esp),%es
FLT3:   mov  UREGS_fs(%esp),%fs
FLT4:   mov  UREGS_gs(%esp),%gs
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
        movl  %eax,UREGS_eax+4(%esp)
        movl  %ebp,UREGS_ebp+4(%esp)
        movl  %edi,UREGS_edi+4(%esp)
        movl  %esi,UREGS_esi+4(%esp)
        movl  %edx,UREGS_edx+4(%esp)
        movl  %ecx,UREGS_ecx+4(%esp)
        movl  %ebx,UREGS_ebx+4(%esp)
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
failsafe_callback:
        GET_CURRENT(%ebx)
        leal  VCPU_trap_bounce(%ebx),%edx
        movl  VCPU_failsafe_addr(%ebx),%eax
        movl  %eax,TRAPBOUNCE_eip(%edx)
        movl  VCPU_failsafe_sel(%ebx),%eax
        movw  %ax,TRAPBOUNCE_cs(%edx)
        movw  $TBF_FAILSAFE,TRAPBOUNCE_flags(%edx)
        call  create_bounce_frame
        xorl  %eax,%eax
        movl  %eax,UREGS_ds(%esp)
        movl  %eax,UREGS_es(%esp)
        movl  %eax,UREGS_fs(%esp)
        movl  %eax,UREGS_gs(%esp)
        jmp   test_all_events
.previous
.section __pre_ex_table,"a"
	.long FLT1,FIX1
	.long FLT2,FIX1
	.long FLT3,FIX1
	.long FLT4,FIX1
	.long FLT5,FIX5
.previous
.section __ex_table,"a"
        .long DBLFLT1,failsafe_callback
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
        PERFC_INCR(PERFC_hypercalls, %eax)
#ifndef NDEBUG
        /* Deliberately corrupt parameter regs not used by this hypercall. */
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
#endif
        call *hypercall_table(,%eax,4)
#ifndef NDEBUG
        /* Deliberately corrupt parameter regs used by this hypercall. */
        addl  $24,%esp     # Shadow parameters
        popl  %ecx         # Shadow EIP
        cmpl  %ecx,UREGS_eip(%esp)
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
FLT6:   mov  VCPU_kernel_ss(%ebx),%gs
        testl $X86_EFLAGS_VM,UREGS_eflags+4(%esp)
        jz   nvm86_1
        subl $16,%esi       /* push ES/DS/FS/GS (VM86 stack frame) */
        movl UREGS_es+4(%esp),%eax
FLT7:   movl %eax,%gs:(%esi)
        movl UREGS_ds+4(%esp),%eax
FLT8:   movl %eax,%gs:4(%esi)
        movl UREGS_fs+4(%esp),%eax
FLT9:   movl %eax,%gs:8(%esi)
        movl UREGS_gs+4(%esp),%eax
FLT10:  movl %eax,%gs:12(%esi)
nvm86_1:subl $8,%esi        /* push SS/ESP (inter-priv iret) */
        movl UREGS_esp+4(%esp),%eax
FLT11:  movl %eax,%gs:(%esi) 
        movl UREGS_ss+4(%esp),%eax
FLT12:  movl %eax,%gs:4(%esi) 
        jmp 1f
ring1:  /* obtain ss/esp from oldss/oldesp -- a ring-1 activation exists */
        movl UREGS_esp+4(%esp),%esi
FLT13:  mov  UREGS_ss+4(%esp),%gs 
1:      /* Construct a stack frame: EFLAGS, CS/EIP */
        movb TRAPBOUNCE_flags(%edx),%cl
        subl $12,%esi
        movl UREGS_eip+4(%esp),%eax
FLT14:  movl %eax,%gs:(%esi) 
        movl VCPU_vcpu_info(%ebx),%eax
        pushl VCPUINFO_upcall_mask(%eax)
        testb $TBF_INTERRUPT,%cl
        setnz %ch                        # TBF_INTERRUPT -> set upcall mask
        orb  %ch,VCPUINFO_upcall_mask(%eax)
        popl %eax
        shll $16,%eax                    # Bits 16-23: saved_upcall_mask
        movw UREGS_cs+4(%esp),%ax        # Bits  0-15: CS
FLT15:  movl %eax,%gs:4(%esi) 
        test $0x00FF0000,%eax            # Bits 16-23: saved_upcall_mask
        setz %ch                         # %ch == !saved_upcall_mask
        movl UREGS_eflags+4(%esp),%eax
        andl $~X86_EFLAGS_IF,%eax
        shlb $1,%ch                      # Bit 9 (EFLAGS.IF)
        orb  %ch,%ah                     # Fold EFLAGS.IF into %eax
FLT16:  movl %eax,%gs:8(%esi)
        test $TBF_EXCEPTION_ERRCODE,%cl
        jz   1f
        subl $4,%esi                    # push error_code onto guest frame
        movl TRAPBOUNCE_error_code(%edx),%eax
FLT17:  movl %eax,%gs:(%esi)
1:      testb $TBF_FAILSAFE,%cl
        jz   2f
        subl $16,%esi                # add DS/ES/FS/GS to failsafe stack frame
        testl $X86_EFLAGS_VM,UREGS_eflags+4(%esp)
        jz   nvm86_2
        xorl %eax,%eax               # VM86: we write zero selector values
FLT18:  movl %eax,%gs:(%esi) 
FLT19:  movl %eax,%gs:4(%esi)
FLT20:  movl %eax,%gs:8(%esi) 
FLT21:  movl %eax,%gs:12(%esi)
        jmp  2f
nvm86_2:movl UREGS_ds+4(%esp),%eax   # non-VM86: write real selector values
FLT22:  movl %eax,%gs:(%esi) 
        movl UREGS_es+4(%esp),%eax
FLT23:  movl %eax,%gs:4(%esi)
        movl UREGS_fs+4(%esp),%eax
FLT24:  movl %eax,%gs:8(%esi) 
        movl UREGS_gs+4(%esp),%eax
FLT25:  movl %eax,%gs:12(%esi)
2:      testl $X86_EFLAGS_VM,UREGS_eflags+4(%esp)
        jz   nvm86_3
        xorl %eax,%eax      /* zero DS-GS, just as a real CPU would */
        movl %eax,UREGS_ds+4(%esp)
        movl %eax,UREGS_es+4(%esp)
        movl %eax,UREGS_fs+4(%esp)
        movl %eax,UREGS_gs+4(%esp)
nvm86_3:/* Rewrite our stack frame and return to ring 1. */
        /* IA32 Ref. Vol. 3: TF, VM, RF and NT flags are cleared on trap. */
        andl $0xfffcbeff,UREGS_eflags+4(%esp)
        mov  %gs,UREGS_ss+4(%esp)
        movl %esi,UREGS_esp+4(%esp)
        movzwl TRAPBOUNCE_cs(%edx),%eax
        movl %eax,UREGS_cs+4(%esp)
        movl TRAPBOUNCE_eip(%edx),%eax
        test %eax,%eax
        jz   domain_crash_synchronous
        movl %eax,UREGS_eip+4(%esp)
        movb $0,TRAPBOUNCE_flags(%edx)
        ret
.section __ex_table,"a"
	.long  FLT6,domain_crash_synchronous ,  FLT7,domain_crash_synchronous
        .long  FLT8,domain_crash_synchronous ,  FLT9,domain_crash_synchronous
        .long FLT10,domain_crash_synchronous , FLT11,domain_crash_synchronous
        .long FLT12,domain_crash_synchronous , FLT13,domain_crash_synchronous
        .long FLT14,domain_crash_synchronous , FLT15,domain_crash_synchronous
        .long FLT16,domain_crash_synchronous , FLT17,domain_crash_synchronous
	.long FLT18,domain_crash_synchronous , FLT19,domain_crash_synchronous
        .long FLT20,domain_crash_synchronous , FLT21,domain_crash_synchronous
        .long FLT22,domain_crash_synchronous , FLT23,domain_crash_synchronous
        .long FLT24,domain_crash_synchronous , FLT25,domain_crash_synchronous
.previous

        ALIGN
process_guest_exception_and_events:
        leal VCPU_trap_bounce(%ebx),%edx
        testb $TBF_EXCEPTION,TRAPBOUNCE_flags(%edx)
        jz   test_all_events
        call create_bounce_frame
        jmp  test_all_events

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
error_code:
        SAVE_ALL_NOSEGREGS(a)
        SET_XEN_SEGMENTS(a)
        testb $X86_EFLAGS_IF>>8,UREGS_eflags+1(%esp)
        jz    exception_with_ints_disabled
        sti                             # re-enable interrupts
        xorl  %eax,%eax
        movw  UREGS_entry_vector(%esp),%ax
        movl  %esp,%edx
	pushl %edx			# push the cpu_user_regs pointer
	GET_CURRENT(%ebx)
        PERFC_INCR(PERFC_exceptions, %eax)
	call  *exception_table(,%eax,4)
        addl  $4,%esp
        movl  UREGS_eflags(%esp),%eax
        movb  UREGS_cs(%esp),%al
        testl $(3|X86_EFLAGS_VM),%eax
	jz    restore_all_xen
        jmp   process_guest_exception_and_events

exception_with_ints_disabled:
        movl  UREGS_eflags(%esp),%eax
        movb  UREGS_cs(%esp),%al
        testl $(3|X86_EFLAGS_VM),%eax   # interrupts disabled outside Xen?
        jnz   FATAL_exception_with_ints_disabled
        pushl %esp
        call  search_pre_exception_table
        addl  $4,%esp
        testl %eax,%eax                 # no fixup code for faulting EIP?
        jz    FATAL_exception_with_ints_disabled
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
	pushl %edx			# push the cpu_user_regs pointer
        pushl %esi                      # push the trapnr (entry vector)
        call  fatal_trap
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
        movl  $(APIC_DM_FIXED | APIC_DEST_SELF | APIC_DEST_LOGICAL | \
                TRAP_deferred_nmi),%ss:APIC_ICR(%eax)
        jmp   restore_all_xen

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

do_arch_sched_op:
        # Ensure we return success even if we return via schedule_tail()
        xorl %eax,%eax
        GET_GUEST_REGS(%ecx)
        movl %eax,UREGS_eax(%ecx)
        jmp  do_sched_op

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
        .long do_arch_sched_op
        .long do_dom0_op
        .long do_set_debugreg
        .long do_get_debugreg
        .long do_update_descriptor  /* 10 */
        .long do_ni_hypercall
        .long do_memory_op
        .long do_multicall
        .long do_update_va_mapping
        .long do_set_timer_op       /* 15 */
        .long do_event_channel_op
        .long do_xen_version
        .long do_console_io
        .long do_physdev_op
        .long do_grant_table_op     /* 20 */
        .long do_vm_assist
        .long do_update_va_mapping_otherdomain
        .long do_iret
        .long do_vcpu_op
        .long do_ni_hypercall       /* 25 */
        .long do_mmuext_op
        .long do_acm_op
        .long do_nmi_op
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
        .byte 2 /* do_arch_sched_op     */
        .byte 1 /* do_dom0_op           */
        .byte 2 /* do_set_debugreg      */
        .byte 1 /* do_get_debugreg      */
        .byte 4 /* do_update_descriptor */  /* 10 */
        .byte 0 /* do_ni_hypercall      */
        .byte 2 /* do_memory_op         */
        .byte 2 /* do_multicall         */
        .byte 4 /* do_update_va_mapping */
        .byte 2 /* do_set_timer_op      */  /* 15 */
        .byte 1 /* do_event_channel_op  */
        .byte 2 /* do_xen_version       */
        .byte 3 /* do_console_io        */
        .byte 1 /* do_physdev_op        */
        .byte 3 /* do_grant_table_op    */  /* 20 */
        .byte 2 /* do_vm_assist         */
        .byte 5 /* do_update_va_mapping_otherdomain */
        .byte 0 /* do_iret              */
        .byte 3 /* do_vcpu_op           */
        .byte 0 /* do_ni_hypercall      */  /* 25 */
        .byte 4 /* do_mmuext_op         */
        .byte 1 /* do_acm_op            */
        .byte 2 /* do_nmi_op            */
        .rept NR_hypercalls-(.-hypercall_args_table)
        .byte 0 /* do_ni_hypercall      */
        .endr
