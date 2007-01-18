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

#define TRACE_VMEXIT(index, value)                              \
    current->arch.hvm_vcpu.hvm_trace_values[index] = (value)

/* save/restore support */

//#define HVM_DEBUG_SUSPEND

extern int hvm_register_savevm(struct domain *d,
                    const char *idstr,
                    int instance_id,
                    int version_id,
                    SaveStateHandler *save_state,
                    LoadStateHandler *load_state,
                    void *opaque);

static inline void hvm_ctxt_seek(hvm_domain_context_t *h, unsigned int pos)
{
    h->cur = pos;
}

static inline uint32_t hvm_ctxt_tell(hvm_domain_context_t *h)
{
    return h->cur;
}

static inline int hvm_ctxt_end(hvm_domain_context_t *h)
{
    return (h->cur >= h->size || h->cur >= HVM_CTXT_SIZE);
}

static inline void hvm_put_byte(hvm_domain_context_t *h, unsigned int i)
{
    if (h->cur >= HVM_CTXT_SIZE) {
        h->cur++;
        return;
    }
    h->data[h->cur++] = (char)i;
}

static inline void hvm_put_8u(hvm_domain_context_t *h, uint8_t b)
{
    hvm_put_byte(h, b);
}

static inline void hvm_put_16u(hvm_domain_context_t *h, uint16_t b)
{
    hvm_put_8u(h, b >> 8);
    hvm_put_8u(h, b);
}

static inline void hvm_put_32u(hvm_domain_context_t *h, uint32_t b)
{
    hvm_put_16u(h, b >> 16);
    hvm_put_16u(h, b);
}

static inline void hvm_put_64u(hvm_domain_context_t *h, uint64_t b)
{
    hvm_put_32u(h, b >> 32);
    hvm_put_32u(h, b);
}

static inline void hvm_put_buffer(hvm_domain_context_t *h, const char *buf, int len)
{
    memcpy(&h->data[h->cur], buf, len);
    h->cur += len;
}


static inline char hvm_get_byte(hvm_domain_context_t *h)
{
    if (h->cur >= HVM_CTXT_SIZE) {
        printk("hvm_get_byte overflow.\n");
        return -1;
    }

    if (h->cur >= h->size) {
        printk("hvm_get_byte exceed data area.\n");
        return -1;
    }

    return h->data[h->cur++];
}

static inline uint8_t hvm_get_8u(hvm_domain_context_t *h)
{
    return hvm_get_byte(h);
}

static inline uint16_t hvm_get_16u(hvm_domain_context_t *h)
{
    uint16_t v;
    v =  hvm_get_8u(h) << 8;
    v |= hvm_get_8u(h);

    return v;
}

static inline uint32_t hvm_get_32u(hvm_domain_context_t *h)
{
    uint32_t v;
    v =  hvm_get_16u(h) << 16;
    v |= hvm_get_16u(h);

    return v;
}

static inline uint64_t hvm_get_64u(hvm_domain_context_t *h)
{
    uint64_t v;
    v =  (uint64_t)hvm_get_32u(h) << 32;
    v |= hvm_get_32u(h);

    return v;
}

static inline void hvm_get_buffer(hvm_domain_context_t *h, char *buf, int len)
{
    memcpy(buf, &h->data[h->cur], len);
    h->cur += len;
}

extern int hvm_save(struct vcpu*, hvm_domain_context_t *h);
extern int hvm_load(struct vcpu*, hvm_domain_context_t *h);

extern int arch_sethvm_ctxt(struct vcpu *v, struct hvm_domain_context *c);
extern int arch_gethvm_ctxt(struct vcpu *v, struct hvm_domain_context *c);

extern void shpage_init(struct domain *d, shared_iopage_t *sp);

extern int hvm_enabled;

int hvm_copy_to_guest_phys(paddr_t paddr, void *buf, int size);
int hvm_copy_from_guest_phys(void *buf, paddr_t paddr, int size);
int hvm_copy_to_guest_virt(unsigned long vaddr, void *buf, int size);
int hvm_copy_from_guest_virt(void *buf, unsigned long vaddr, int size);

void hvm_print_line(struct vcpu *v, const char c);
void hlt_timer_fn(void *data);

void hvm_do_hypercall(struct cpu_user_regs *pregs);

void hvm_hlt(unsigned long rflags);
void hvm_triple_fault(void);

#endif /* __ASM_X86_HVM_SUPPORT_H__ */
