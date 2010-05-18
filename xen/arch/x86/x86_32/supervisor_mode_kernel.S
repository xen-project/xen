/*
 * Handle stack fixup for guest running in RING 0.
 *
 * Copyright (c) 2006 Ian Campbell
 *
 * When a guest kernel is allowed to run in RING 0 a hypercall,
 * interrupt or exception interrupting the guest kernel will not cause
 * a privilege level change and therefore the stack will not be swapped
 * to the Xen stack.
 *
 * To fix this we look for RING 0 activation frames with a stack
 * pointer below HYPERVISOR_VIRT_START (indicating a guest kernel
 * frame) and fix this up by locating the Xen stack via the TSS
 * and moving the activation frame to the Xen stack. In the process we
 * convert the frame into an inter-privilege frame returning to RING 1
 * so that we can catch and reverse the process on exit.
 */

#include <xen/config.h>
#include <asm/asm_defns.h>
#include <public/xen.h>

#define guestreg(field) ((field)-UREGS_eip+36)

        # Upon entry the stack should be the Xen stack and contain:
        #   %ss, %esp, EFLAGS, %cs|1, %eip, RETURN
        # On exit the stack should be %ss:%esp (i.e. the guest stack)
        # and contain:
        #   EFLAGS, %cs, %eip, RETURN
        ALIGN
ENTRY(restore_ring0_guest)
        pusha

        # Point %gs:%esi to guest stack.
RRG0:   movw guestreg(UREGS_ss)(%esp),%gs
        movl guestreg(UREGS_esp)(%esp),%esi

        # Copy EFLAGS, %cs, %eip, RETURN, PUSHA from Xen stack to guest stack.
        movl $12,%ecx /* 12 32-bit values */

1:      subl $4,%esi
        movl -4(%esp,%ecx,4),%eax
RRG1:   movl %eax,%gs:(%esi)
        loop 1b

RRG2:   andl $~3,%gs:guestreg(UREGS_cs)(%esi)

        movl %gs,%eax

        # We need to do this because these registers are not present
        # on the guest stack so they cannot be restored by the code in
        # restore_all_guest.
RRG3:   mov  guestreg(UREGS_ds)(%esp),%ds
RRG4:   mov  guestreg(UREGS_es)(%esp),%es
RRG5:   mov  guestreg(UREGS_fs)(%esp),%fs
RRG6:   mov  guestreg(UREGS_gs)(%esp),%gs

RRG7:   movl %eax,%ss
        movl %esi,%esp

        popa
        ret
.section __ex_table,"a"
        .long RRG0,domain_crash_synchronous
        .long RRG1,domain_crash_synchronous
        .long RRG2,domain_crash_synchronous
        .long RRG3,domain_crash_synchronous
        .long RRG4,domain_crash_synchronous
        .long RRG5,domain_crash_synchronous
        .long RRG6,domain_crash_synchronous
        .long RRG7,domain_crash_synchronous
.previous

        # Upon entry the stack should be a guest stack and contain:
        #   EFLAGS, %cs, %eip, ERROR, RETURN
        # On exit the stack should be the Xen stack and contain:
        #   %ss, %esp, EFLAGS, %cs|1, %eip, ERROR, RETURN
        ALIGN
ENTRY(fixup_ring0_guest_stack)
        pushl %eax
        pushl %ecx
        pushl %ds
        pushl %gs
        pushl %esi

        movw  $__HYPERVISOR_DS,%ax
        movw  %ax,%ds

        # Point %gs:%esi to guest stack frame.
        movw  %ss,%ax
        movw  %ax,%gs
        movl  %esp,%esi
        # Account for entries on the guest stack:
        # * Pushed by normal exception/interrupt/hypercall mechanisms
        #   * EFLAGS, %cs, %eip, ERROR == 4 words.
        # * Pushed by the fixup routine
        #   * [RETURN], %eax, %ecx, %ds, %gs and %esi == 6 words.
        addl $((6+4)*4),%esi

        # %gs:%esi now points to the guest stack before the
        # interrupt/exception occurred.

        movl  $PER_CPU_GDT_ENTRY*8,%ecx
        lsll  %ecx,%ecx
        movl  __per_cpu_offset(,%ecx,4),%ecx
        addl  $per_cpu__init_tss,%ecx

        # Load Xen stack from TSS.
        movw  TSS_ss0(%ecx),%ax
TRP1:   movw  %ax,%ss
        movl  TSS_esp0(%ecx),%esp

        pushl %gs
        pushl %esi

        # Move EFLAGS, %cs, %eip, ERROR, RETURN, %eax, %ecx, %ds, %gs, %esi
        # from guest stack to Xen stack.
        movl  $10,%ecx
1:      subl  $4,%esp
        subl  $4,%esi
TRP2:   movl  %gs:(%esi),%eax
        movl  %eax,(%esp)
        loop  1b

        # CS = CS|1 to simulate RING1 stack frame.
        orl   $1,32(%esp)

        popl  %esi
        popl  %gs
        popl  %ds
        popl  %ecx
        popl  %eax
        ret
.section __ex_table,"a"
        .long TRP1,domain_crash_synchronous
        .long TRP2,domain_crash_synchronous
.previous

domain_crash_synchronous_string:
        .asciz "domain_crash_sync called from supervisor_mode_kernel.S (%lx)\n"

domain_crash_synchronous:
        pushl $domain_crash_synchronous_string
        call  printk
        jmp   __domain_crash_synchronous
