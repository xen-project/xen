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
#include <xen/hvm/save.h>
#include <asm/types.h>
#include <asm/regs.h>
#include <asm/processor.h>

#ifndef NDEBUG
#define HVM_DEBUG 1
#else
#define HVM_DEBUG 1
#endif

static inline vcpu_iodata_t *get_ioreq(struct vcpu *v)
{
    struct domain *d = v->domain;
    shared_iopage_t *p = d->arch.hvm_domain.ioreq.va;
    ASSERT((v == current) || spin_is_locked(&d->arch.hvm_domain.ioreq.lock));
    ASSERT(d->arch.hvm_domain.ioreq.va != NULL);
    return &p->vcpu_iodata[v->vcpu_id];
}

/* XXX these are really VMX specific */
#define TYPE_MOV_TO_DR          (0 << 4)
#define TYPE_MOV_FROM_DR        (1 << 4)
#define TYPE_MOV_TO_CR          (0 << 4)
#define TYPE_MOV_FROM_CR        (1 << 4)
#define TYPE_CLTS               (2 << 4)
#define TYPE_LMSW               (3 << 4)

#define HVM_DELIVER_NO_ERROR_CODE  -1

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
#define DBG_LEVEL_HCALL             (1 << 10)
#define DBG_LEVEL_MSR               (1 << 11)

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

extern char hvm_io_bitmap[];

void hvm_enable(struct hvm_function_table *);

enum hvm_copy_result {
    HVMCOPY_okay = 0,
    HVMCOPY_bad_gva_to_gfn,
    HVMCOPY_bad_gfn_to_mfn
};

/*
 * Copy to/from a guest physical address.
 * Returns HVMCOPY_okay, else HVMCOPY_bad_gfn_to_mfn if the given physical
 * address range does not map entirely onto ordinary machine memory.
 */
enum hvm_copy_result hvm_copy_to_guest_phys(
    paddr_t paddr, void *buf, int size);
enum hvm_copy_result hvm_copy_from_guest_phys(
    void *buf, paddr_t paddr, int size);

/*
 * Copy to/from a guest virtual address.
 * Returns:
 *  HVMCOPY_okay: Copy was entirely successful.
 *  HVMCOPY_bad_gfn_to_mfn: Some guest physical address did not map to
 *                          ordinary machine memory.
 *  HVMCOPY_bad_gva_to_gfn: Some guest virtual address did not have a valid
 *                          mapping to a guest physical address. In this case
 *                          a page fault exception is automatically queued
 *                          for injection into the current HVM VCPU.
 */
enum hvm_copy_result hvm_copy_to_guest_virt(
    unsigned long vaddr, void *buf, int size);
enum hvm_copy_result hvm_copy_from_guest_virt(
    void *buf, unsigned long vaddr, int size);
enum hvm_copy_result hvm_fetch_from_guest_virt(
    void *buf, unsigned long vaddr, int size);

/*
 * As above (copy to/from a guest virtual address), but no fault is generated
 * when HVMCOPY_bad_gva_to_gfn is returned.
 */
enum hvm_copy_result hvm_copy_to_guest_virt_nofault(
    unsigned long vaddr, void *buf, int size);
enum hvm_copy_result hvm_copy_from_guest_virt_nofault(
    void *buf, unsigned long vaddr, int size);
enum hvm_copy_result hvm_fetch_from_guest_virt_nofault(
    void *buf, unsigned long vaddr, int size);

void hvm_print_line(struct vcpu *v, const char c);
void hlt_timer_fn(void *data);

#define HVM_HCALL_completed  0 /* hypercall completed - no further action */
#define HVM_HCALL_preempted  1 /* hypercall preempted - re-execute VMCALL */
#define HVM_HCALL_invalidate 2 /* invalidate ioemu-dm memory cache        */
int hvm_do_hypercall(struct cpu_user_regs *pregs);

void hvm_hlt(unsigned long rflags);
void hvm_triple_fault(void);

int hvm_set_efer(uint64_t value);
int hvm_set_cr0(unsigned long value);
int hvm_set_cr3(unsigned long value);
int hvm_set_cr4(unsigned long value);

#endif /* __ASM_X86_HVM_SUPPORT_H__ */
