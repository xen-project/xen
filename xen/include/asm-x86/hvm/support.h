/*
 * support.h: HVM support routines used by VT-x and SVM.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
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

#ifndef __ASM_X86_HVM_SUPPORT_H__
#define __ASM_X86_HVM_SUPPORT_H__

#include <xen/sched.h>
#include <asm/types.h>
#include <asm/regs.h>
#include <asm/processor.h>

#ifndef NDEBUG
#define HVM_DEBUG 1
#else
#define HVM_DEBUG 1
#endif

#define hvm_guest(v) ((v)->arch.guest_context.flags & VGCF_HVM_GUEST)

static inline shared_iopage_t *get_sp(struct domain *d)
{
    return (shared_iopage_t *) d->arch.hvm_domain.shared_page_va;
}

static inline vcpu_iodata_t *get_vio(struct domain *d, unsigned long cpu)
{
    return &get_sp(d)->vcpu_iodata[cpu];
}

/* XXX these are really VMX specific */
#define TYPE_MOV_TO_DR          (0 << 4)
#define TYPE_MOV_FROM_DR        (1 << 4)
#define TYPE_MOV_TO_CR          (0 << 4)
#define TYPE_MOV_FROM_CR        (1 << 4)
#define TYPE_CLTS               (2 << 4)
#define TYPE_LMSW               (3 << 4)

enum hval_bitmaps {
    EXCEPTION_BITMAP_TABLE=0,
};
 
#define EXCEPTION_BITMAP_DE     (1 << 0)        /* Divide Error */
#define EXCEPTION_BITMAP_DB     (1 << 1)        /* Debug */
#define EXCEPTION_BITMAP_NMI    (1 << 2)        /* NMI */
#define EXCEPTION_BITMAP_BP     (1 << 3)        /* Breakpoint */
#define EXCEPTION_BITMAP_OF     (1 << 4)        /* Overflow */
#define EXCEPTION_BITMAP_BR     (1 << 5)        /* BOUND Range Exceeded */
#define EXCEPTION_BITMAP_UD     (1 << 6)        /* Invalid Opcode */
#define EXCEPTION_BITMAP_NM     (1 << 7)        /* Device Not Available */
#define EXCEPTION_BITMAP_DF     (1 << 8)        /* Double Fault */
/* reserved */
#define EXCEPTION_BITMAP_TS     (1 << 10)       /* Invalid TSS */
#define EXCEPTION_BITMAP_NP     (1 << 11)       /* Segment Not Present */
#define EXCEPTION_BITMAP_SS     (1 << 12)       /* Stack-Segment Fault */
#define EXCEPTION_BITMAP_GP     (1 << 13)       /* General Protection */
#define EXCEPTION_BITMAP_PG     (1 << 14)       /* Page Fault */
#define EXCEPTION_BITMAP_MF     (1 << 16)       /* x87 FPU Floating-Point Error (Math Fault)  */
#define EXCEPTION_BITMAP_AC     (1 << 17)       /* Alignment Check */
#define EXCEPTION_BITMAP_MC     (1 << 18)       /* Machine Check */
#define EXCEPTION_BITMAP_XF     (1 << 19)       /* SIMD Floating-Point Exception */

/* Pending Debug exceptions */
#define PENDING_DEBUG_EXC_BP    (1 << 12)       /* break point */
#define PENDING_DEBUG_EXC_BS    (1 << 14)       /* Single step */

#ifdef XEN_DEBUGGER
#define MONITOR_DEFAULT_EXCEPTION_BITMAP        \
    ( EXCEPTION_BITMAP_PG |                     \
      EXCEPTION_BITMAP_DB |                     \
      EXCEPTION_BITMAP_BP |                     \
      EXCEPTION_BITMAP_GP )
#else
#define MONITOR_DEFAULT_EXCEPTION_BITMAP        \
    ( EXCEPTION_BITMAP_PG |                     \
      EXCEPTION_BITMAP_BP )
#endif

#define PC_DEBUG_PORT   0x80

#define VMX_DELIVER_NO_ERROR_CODE  -1

/*
 * This works for both 32bit & 64bit eflags filteration
 * done in construct_init_vmc[sb]_guest()
 */
#define HVM_EFLAGS_RESERVED_0          0xffc08028 /* bitmap for 0 */
#define HVM_EFLAGS_RESERVED_1          0x00000002 /* bitmap for 1 */

#if HVM_DEBUG
#define DBG_LEVEL_0                 (1 << 0)
#define DBG_LEVEL_1                 (1 << 1)
#define DBG_LEVEL_2                 (1 << 2)
#define DBG_LEVEL_3                 (1 << 3)
#define DBG_LEVEL_IO                (1 << 4)
#define DBG_LEVEL_VMMU              (1 << 5)
#define DBG_LEVEL_VLAPIC            (1 << 6)
#define DBG_LEVEL_VLAPIC_TIMER      (1 << 7)
#define DBG_LEVEL_VLAPIC_INTERRUPT  (1 << 8)
#define DBG_LEVEL_IOAPIC            (1 << 9)

extern unsigned int opt_hvm_debug_level;
#define HVM_DBG_LOG(level, _f, _a...)                                         \
    do {                                                                      \
        if ( unlikely((level) & opt_hvm_debug_level) )                        \
            printk("[HVM:%d.%d] <%s> " _f "\n",                               \
                   current->domain->domain_id, current->vcpu_id, __func__,    \
                   ## _a);                                                    \
    } while (0)
#else
#define HVM_DBG_LOG(level, _f, _a...)
#endif

#define  __hvm_bug(regs)                                        \
    do {                                                        \
        printk("__hvm_bug at %s:%d\n", __FILE__, __LINE__);     \
        show_execution_state(regs);                             \
        domain_crash_synchronous();                             \
    } while (0)

extern int hvm_enabled;

int hvm_copy_to_guest_phys(unsigned long paddr, void *buf, int size);
int hvm_copy_from_guest_phys(void *buf, unsigned long paddr, int size);
int hvm_copy_to_guest_virt(unsigned long vaddr, void *buf, int size);
int hvm_copy_from_guest_virt(void *buf, unsigned long vaddr, int size);

void hvm_setup_platform(struct domain* d);
int hvm_mmio_intercept(ioreq_t *p);
int hvm_io_intercept(ioreq_t *p, int type);
int hvm_buffered_io_intercept(ioreq_t *p);
void hvm_hooks_assist(struct vcpu *v);
void hvm_print_line(struct vcpu *v, const char c);
void hlt_timer_fn(void *data);

void hvm_do_hypercall(struct cpu_user_regs *pregs);

void hvm_prod_vcpu(struct vcpu *v);

void hvm_hlt(unsigned long rflags);

#endif /* __ASM_X86_HVM_SUPPORT_H__ */
