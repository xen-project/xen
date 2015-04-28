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
#include <xen/iocap.h>
#include <xsm/xsm.h>
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
    case XEN_DOMCTL_bind_pt_irq:
    {
        int rc;
        xen_domctl_bind_pt_irq_t *bind = &domctl->u.bind_pt_irq;
        uint32_t irq = bind->u.spi.spi;
        uint32_t virq = bind->machine_irq;

        /* We only support PT_IRQ_TYPE_SPI */
        if ( bind->irq_type != PT_IRQ_TYPE_SPI )
            return -EOPNOTSUPP;

        /*
         * XXX: For now map the interrupt 1:1. Other support will require to
         * modify domain_pirq_to_irq macro.
         */
        if ( irq != virq )
            return -EINVAL;

        /*
         * ARM doesn't require separating IRQ assignation into 2
         * hypercalls (PHYSDEVOP_map_pirq and DOMCTL_bind_pt_irq).
         *
         * Call xsm_map_domain_irq in order to keep the same XSM checks
         * done by the 2 hypercalls for consistency with other
         * architectures.
         */
        rc = xsm_map_domain_irq(XSM_HOOK, d, irq, NULL);
        if ( rc )
            return rc;

        rc = xsm_bind_pt_irq(XSM_HOOK, d, bind);
        if ( rc )
            return rc;

        if ( !irq_access_permitted(current->domain, irq) )
            return -EPERM;

        if ( !vgic_reserve_virq(d, virq) )
            return -EBUSY;

        rc = route_irq_to_guest(d, virq, irq, "routed IRQ");
        if ( rc )
            vgic_free_virq(d, virq);

        return rc;
    }
    case XEN_DOMCTL_unbind_pt_irq:
    {
        int rc;
        xen_domctl_bind_pt_irq_t *bind = &domctl->u.bind_pt_irq;
        uint32_t irq = bind->u.spi.spi;
        uint32_t virq = bind->machine_irq;

        /* We only support PT_IRQ_TYPE_SPI */
        if ( bind->irq_type != PT_IRQ_TYPE_SPI )
            return -EOPNOTSUPP;

        /* For now map the interrupt 1:1 */
        if ( irq != virq )
            return -EINVAL;

        rc = xsm_unbind_pt_irq(XSM_HOOK, d, bind);
        if ( rc )
            return rc;

        if ( !irq_access_permitted(current->domain, irq) )
            return -EPERM;

        rc = release_guest_irq(d, virq);
        if ( rc )
            return rc;

        vgic_free_virq(d, virq);

        return 0;
    }
    default:
    {
        int rc;

        rc = subarch_do_domctl(domctl, d, u_domctl);

        if ( rc == -ENOSYS )
            rc = iommu_do_domctl(domctl, d, u_domctl);

        return rc;
    }
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
