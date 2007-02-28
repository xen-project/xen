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

/*
 * Save/restore support 
 */

/* Marshalling and unmarshalling uses a buffer with size and cursor. */
typedef struct hvm_domain_context {
    uint32_t cur;
    uint32_t size;
    uint8_t *data;
} hvm_domain_context_t;

/* Marshalling an entry: check space and fill in the header */
static inline int _hvm_init_entry(struct hvm_domain_context *h,
                                  uint16_t tc, uint16_t inst, uint32_t len)
{
    struct hvm_save_descriptor *d 
        = (struct hvm_save_descriptor *)&h->data[h->cur];
    if ( h->size - h->cur < len + sizeof (*d) )
    {
        gdprintk(XENLOG_WARNING,
                 "HVM save: no room for %"PRIu32" + %u bytes "
                 "for typecode %"PRIu16"\n",
                 len, (unsigned) sizeof (*d), tc);
        return -1;
    }
    d->typecode = tc;
    d->instance = inst;
    d->length = len;
    h->cur += sizeof (*d);
    return 0;
}

/* Marshalling: copy the contents in a type-safe way */
#define _hvm_write_entry(_x, _h, _src) do {                     \
    *(HVM_SAVE_TYPE(_x) *)(&(_h)->data[(_h)->cur]) = *(_src);   \
    (_h)->cur += HVM_SAVE_LENGTH(_x);                           \
} while (0)

/* Marshalling: init and copy; evaluates to zero on success */
#define hvm_save_entry(_x, _inst, _h, _src) ({          \
    int r;                                              \
    r = _hvm_init_entry((_h), HVM_SAVE_CODE(_x),        \
                        (_inst), HVM_SAVE_LENGTH(_x));  \
    if ( r == 0 )                                       \
        _hvm_write_entry(_x, (_h), (_src));             \
    r; })

/* Unmarshalling: test an entry's size and typecode and record the instance */
static inline int _hvm_check_entry(struct hvm_domain_context *h, 
                                   uint16_t type, uint32_t len)
{
    struct hvm_save_descriptor *d 
        = (struct hvm_save_descriptor *)&h->data[h->cur];
    if ( len + sizeof (*d) > h->size - h->cur)
    {
        gdprintk(XENLOG_WARNING, 
                 "HVM restore: not enough data left to read %u bytes "
                 "for type %u\n", len, type);
        return -1;
    }    
    if ( type != d->typecode || len != d->length )
    {
        gdprintk(XENLOG_WARNING, 
                 "HVM restore mismatch: expected type %u length %u, "
                 "saw type %u length %u\n", type, len, d->typecode, d->length);
        return -1;
    }
    h->cur += sizeof (*d);
    return 0;
}

/* Unmarshalling: copy the contents in a type-safe way */
#define _hvm_read_entry(_x, _h, _dst) do {                      \
    *(_dst) = *(HVM_SAVE_TYPE(_x) *) (&(_h)->data[(_h)->cur]);  \
    (_h)->cur += HVM_SAVE_LENGTH(_x);                           \
} while (0)

/* Unmarshalling: check, then copy. Evaluates to zero on success. */
#define hvm_load_entry(_x, _h, _dst) ({                                 \
    int r;                                                              \
    r = _hvm_check_entry((_h), HVM_SAVE_CODE(_x), HVM_SAVE_LENGTH(_x)); \
    if ( r == 0 )                                                       \
        _hvm_read_entry(_x, (_h), (_dst));                              \
    r; })

/* Unmarshalling: what is the instance ID of the next entry? */
static inline uint16_t hvm_load_instance(struct hvm_domain_context *h)
{
    struct hvm_save_descriptor *d 
        = (struct hvm_save_descriptor *)&h->data[h->cur];
    return d->instance;
}

/* Handler types for different types of save-file entry. 
 * The save handler may save multiple instances of a type into the buffer;
 * the load handler will be called once for each instance found when
 * restoring.  Both return non-zero on error. */
typedef int (*hvm_save_handler) (struct domain *d, 
                                 hvm_domain_context_t *h);
typedef int (*hvm_load_handler) (struct domain *d,
                                 hvm_domain_context_t *h);

/* Init-time function to declare a pair of handlers for a type,
 * and the maximum buffer space needed to save this type of state */
void hvm_register_savevm(uint16_t typecode,
                         const char *name, 
                         hvm_save_handler save_state,
                         hvm_load_handler load_state,
                         size_t size, int kind);

/* The space needed for saving can be per-domain or per-vcpu: */
#define HVMSR_PER_DOM  0
#define HVMSR_PER_VCPU 1

/* Syntactic sugar around that function: specify the max number of
 * saves, and this calculates the size of buffer needed */
#define HVM_REGISTER_SAVE_RESTORE(_x, _save, _load, _num, _k)             \
static int __hvm_register_##_x##_save_and_restore(void)                   \
{                                                                         \
    hvm_register_savevm(HVM_SAVE_CODE(_x),                                \
                        #_x,                                              \
                        &_save,                                           \
                        &_load,                                           \
                        (_num) * (HVM_SAVE_LENGTH(_x)                     \
                                  + sizeof (struct hvm_save_descriptor)), \
                        _k);                                              \
    return 0;                                                             \
}                                                                         \
__initcall(__hvm_register_##_x##_save_and_restore);


/* Entry points for saving and restoring HVM domain state */
size_t hvm_save_size(struct domain *d);
int hvm_save(struct domain *d, hvm_domain_context_t *h);
int hvm_load(struct domain *d, hvm_domain_context_t *h);

/* End of save/restore */

extern char hvm_io_bitmap[];
extern int hvm_enabled;

void hvm_enable(struct hvm_function_table *);
void hvm_disable(void);

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
