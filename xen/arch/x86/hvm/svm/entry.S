/*
 * entry.S: SVM architecture-specific entry/exit handling.
 * Copyright (c) 2005-2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/softirq.h>
#include <asm/types.h>
#include <asm/asm_defns.h>
#include <asm/apicdef.h>
#include <asm/page.h>
#include <public/xen.h>

#define VMRUN  .byte 0x0F,0x01,0xD8
#define STGI   .byte 0x0F,0x01,0xDC
#define CLGI   .byte 0x0F,0x01,0xDD

#define get_current(reg) GET_CURRENT(r(reg))
        
#if defined(__x86_64__)
#define r(reg) %r##reg
#define addr_of(lbl) lbl(%rip)
#define call_with_regs(fn)                      \
        mov  %rsp,%rdi;                         \
        call fn;
#else /* defined(__i386__) */
#define r(reg) %e##reg
#define addr_of(lbl) lbl
#define UREGS_rax UREGS_eax
#define UREGS_rip UREGS_eip
#define UREGS_rsp UREGS_esp
#define call_with_regs(fn)                      \
        mov  %esp,%eax;                         \
        push %eax;                              \
        call fn;                                \
        add  $4,%esp;
#endif

ENTRY(svm_asm_do_resume)
        call svm_intr_assist
        call_with_regs(nsvm_vcpu_switch)

        get_current(bx)
        CLGI

        mov  VCPU_processor(r(bx)),%eax
        shl  $IRQSTAT_shift,r(ax)
        lea  addr_of(irq_stat),r(dx)
        testl $~0,(r(dx),r(ax),1)
        jnz  .Lsvm_process_softirqs

        testb $0, VCPU_nsvm_hap_enabled(r(bx))
UNLIKELY_START(nz, nsvm_hap)
        mov  VCPU_nhvm_p2m(r(bx)),r(ax)
        test r(ax),r(ax)
        sete %al
        andb VCPU_nhvm_guestmode(r(bx)),%al
        jnz  .Lsvm_nsvm_no_p2m
UNLIKELY_END(nsvm_hap)

        call svm_asid_handle_vmrun

        cmpb $0,addr_of(tb_init_done)
UNLIKELY_START(nz, svm_trace)
        call svm_trace_vmentry
UNLIKELY_END(svm_trace)

        mov  VCPU_svm_vmcb(r(bx)),r(cx)
        mov  UREGS_rax(r(sp)),r(ax)
        mov  r(ax),VMCB_rax(r(cx))
        mov  UREGS_rip(r(sp)),r(ax)
        mov  r(ax),VMCB_rip(r(cx))
        mov  UREGS_rsp(r(sp)),r(ax)
        mov  r(ax),VMCB_rsp(r(cx))
        mov  UREGS_eflags(r(sp)),r(ax)
        mov  r(ax),VMCB_rflags(r(cx))

        mov  VCPU_svm_vmcb_pa(r(bx)),r(ax)

#if defined(__x86_64__)
        pop  %r15
        pop  %r14
        pop  %r13
        pop  %r12
        pop  %rbp
        pop  %rbx
        pop  %r11
        pop  %r10
        pop  %r9
        pop  %r8
        add  $8,%rsp /* Skip %rax: restored by VMRUN. */
        pop  %rcx
        pop  %rdx
        pop  %rsi
        pop  %rdi
#else /* defined(__i386__) */
        pop  %ebx
        pop  %ecx
        pop  %edx
        pop  %esi
        pop  %edi
        pop  %ebp
#endif

        VMRUN

#if defined(__x86_64__)
        push %rdi
        push %rsi
        push %rdx
        push %rcx
        push %rax
        push %r8
        push %r9
        push %r10
        push %r11
        push %rbx
        push %rbp
        push %r12
        push %r13
        push %r14
        push %r15
#else /* defined(__i386__) */
        push %ebp
        push %edi
        push %esi
        push %edx
        push %ecx
        push %ebx
#endif

        get_current(bx)
        movb $0,VCPU_svm_vmcb_in_sync(r(bx))
        mov  VCPU_svm_vmcb(r(bx)),r(cx)
        mov  VMCB_rax(r(cx)),r(ax)
        mov  r(ax),UREGS_rax(r(sp))
        mov  VMCB_rip(r(cx)),r(ax)
        mov  r(ax),UREGS_rip(r(sp))
        mov  VMCB_rsp(r(cx)),r(ax)
        mov  r(ax),UREGS_rsp(r(sp))
        mov  VMCB_rflags(r(cx)),r(ax)
        mov  r(ax),UREGS_eflags(r(sp))

#ifndef NDEBUG
        mov  $0xbeef,%ax
        mov  %ax,UREGS_error_code(r(sp))
        mov  %ax,UREGS_entry_vector(r(sp))
        mov  %ax,UREGS_saved_upcall_mask(r(sp))
        mov  %ax,UREGS_cs(r(sp))
        mov  %ax,UREGS_ds(r(sp))
        mov  %ax,UREGS_es(r(sp))
        mov  %ax,UREGS_fs(r(sp))
        mov  %ax,UREGS_gs(r(sp))
        mov  %ax,UREGS_ss(r(sp))
#endif

        STGI
.globl svm_stgi_label
svm_stgi_label:
        call_with_regs(svm_vmexit_handler)
        jmp  svm_asm_do_resume

.Lsvm_process_softirqs:
        STGI
        call do_softirq
        jmp  svm_asm_do_resume

.Lsvm_nsvm_no_p2m:
        /* Someone shot down our nested p2m table; go round again
         * and nsvm_vcpu_switch() will fix it for us. */
        STGI
        jmp  svm_asm_do_resume
