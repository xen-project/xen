/******************************************************************************
 * Arch-specific domctl.c
 *
 * Copyright (c) 2012, Citrix Systems
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/hypercall.h>
#include <public/domctl.h>

long arch_do_domctl(struct xen_domctl *domctl, struct domain *d,
                    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    switch ( domctl->cmd )
    {
    case XEN_DOMCTL_cacheflush:
    {
        unsigned long s = domctl->u.cacheflush.start_pfn;
        unsigned long e = s + domctl->u.cacheflush.nr_pfns;

        if ( domctl->u.cacheflush.nr_pfns > (1U<<MAX_ORDER) )
            return -EINVAL;

        if ( e < s )
            return -EINVAL;

        return p2m_cache_flush(d, s, e);
    }

    default:
        return subarch_do_domctl(domctl, d, u_domctl);
    }
}

void arch_get_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
    struct vcpu_guest_context *ctxt = c.nat;
    struct vcpu_guest_core_regs *regs = &c.nat->user_regs;

    vcpu_regs_hyp_to_user(v, regs);

    ctxt->sctlr = v->arch.sctlr;
    ctxt->ttbr0 = v->arch.ttbr0;
    ctxt->ttbr1 = v->arch.ttbr1;
    ctxt->ttbcr = v->arch.ttbcr;

    if ( !test_bit(_VPF_down, &v->pause_flags) )
        ctxt->flags |= VGCF_online;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
