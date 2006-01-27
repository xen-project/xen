/******************************************************************************
 * asm-ia64/hypercall.h
 */

#ifndef __ASM_IA64_HYPERCALL_H__
#define __ASM_IA64_HYPERCALL_H__

#include <public/xen.h>
#include <asm/types.h>
#include <asm/vcpu.h>

extern int
vmx_do_mmu_update(
    mmu_update_t *ureqs,
    u64 count,
    u64 *pdone,
    u64 foreigndom);

extern int
do_lock_page(
    VCPU *vcpu,
    u64 va,
    u64 lock);

extern int
do_set_shared_page(
    VCPU *vcpu,
    u64 gpa);

#endif /* __ASM_IA64_HYPERCALL_H__ */
