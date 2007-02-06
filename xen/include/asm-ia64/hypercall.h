/******************************************************************************
 * asm-ia64/hypercall.h
 */

#ifndef __ASM_IA64_HYPERCALL_H__
#define __ASM_IA64_HYPERCALL_H__

#include <public/xen.h>
#include <asm/types.h>
#include <asm/vcpu.h>

extern long
do_event_channel_op_compat(
    XEN_GUEST_HANDLE(evtchn_op_t) uop);

extern long do_pirq_guest_eoi(int pirq);

extern int
vmx_do_mmu_update(
    mmu_update_t *ureqs,
    u64 count,
    u64 *pdone,
    u64 foreigndom);

#define arch_do_vcpu_op(cmd, vcpu, arg) (-ENOSYS)

#endif /* __ASM_IA64_HYPERCALL_H__ */
