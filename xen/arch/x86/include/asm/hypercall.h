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

#ifndef NDEBUG
static inline unsigned int _get_nargs(const unsigned char *tbl, unsigned int c)
{
    return tbl[c];
}
#define get_nargs(t, c) _get_nargs(t, array_index_nospec(c, ARRAY_SIZE(t)))
#else
#define get_nargs(tbl, c) 0
#endif

static inline void clobber_regs(struct cpu_user_regs *regs,
                                unsigned int nargs)
{
#ifndef NDEBUG
    /* Deliberately corrupt used parameter regs. */
    switch ( nargs )
    {
    case 5: regs->r8  = 0xdeadbeefdeadf00dUL; fallthrough;
    case 4: regs->r10 = 0xdeadbeefdeadf00dUL; fallthrough;
    case 3: regs->rdx = 0xdeadbeefdeadf00dUL; fallthrough;
    case 2: regs->rsi = 0xdeadbeefdeadf00dUL; fallthrough;
    case 1: regs->rdi = 0xdeadbeefdeadf00dUL;
    }
#endif
}

static inline void clobber_regs32(struct cpu_user_regs *regs,
                                  unsigned int nargs)
{
#ifndef NDEBUG
    /* Deliberately corrupt used parameter regs. */
    switch ( nargs )
    {
    case 5: regs->edi = 0xdeadf00dU; fallthrough;
    case 4: regs->esi = 0xdeadf00dU; fallthrough;
    case 3: regs->edx = 0xdeadf00dU; fallthrough;
    case 2: regs->ecx = 0xdeadf00dU; fallthrough;
    case 1: regs->ebx = 0xdeadf00dU;
    }
#endif
}

#endif /* __ASM_X86_HYPERCALL_H__ */
