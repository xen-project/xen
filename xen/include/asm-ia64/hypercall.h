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

#endif /* __ASM_IA64_HYPERCALL_H__ */
