/******************************************************************************
 * asm-x86/hypercall.h
 */

#ifndef __XEN_HYPERCALL_H__
#error "asm/hypercall.h should not be included directly - include xen/hypercall.h instead"
#endif

#ifndef __ASM_X86_HYPERCALL_H__
#define __ASM_X86_HYPERCALL_H__

#include <xen/types.h>
#include <public/physdev.h>
#include <public/event_channel.h>
#include <public/arch-x86/xen-mca.h> /* for do_mca */
#include <asm/paging.h>

#define __HYPERVISOR_paging_domctl_cont __HYPERVISOR_arch_1

typedef unsigned long hypercall_fn_t(
    unsigned long, unsigned long, unsigned long,
    unsigned long, unsigned long);

typedef struct {
    uint8_t native;
#ifdef CONFIG_COMPAT
    uint8_t compat;
#endif
} hypercall_args_t;

extern const hypercall_args_t hypercall_args_table[NR_hypercalls];

#ifdef CONFIG_PV
void pv_hypercall(struct cpu_user_regs *regs);
#endif

void pv_ring1_init_hypercall_page(void *ptr);
void pv_ring3_init_hypercall_page(void *ptr);

/*
 * Both do_mmuext_op() and do_mmu_update():
 * We steal the m.s.b. of the @count parameter to indicate whether this
 * invocation of do_mmu_update() is resuming a previously preempted call.
 */
#define MMU_UPDATE_PREEMPTED          (~(~0U>>1))

#ifdef CONFIG_COMPAT

#include <compat/arch-x86/xen.h>
#include <compat/physdev.h>
#include <compat/platform.h>

extern int
compat_common_vcpu_op(
    int cmd, struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg);

#endif /* CONFIG_COMPAT */

#endif /* __ASM_X86_HYPERCALL_H__ */
