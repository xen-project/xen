/******************************************************************************
 * Arch-specific domctl.c
 *
 * Copyright (c) 2012, Citrix Systems
 */

#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/iocap.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/types.h>
#include <xsm/xsm.h>
#include <public/domctl.h>

void arch_get_domain_info(const struct domain *d,
                          struct xen_domctl_getdomaininfo *info)
{
    /* All ARM domains use hardware assisted paging. */
    info->flags |= XEN_DOMINF_hap;
}

static int handle_vuart_init(struct domain *d, 
                             struct xen_domctl_vuart_op *vuart_op)
{
    int rc;
    struct vpl011_init_info info;

    info.console_domid = vuart_op->console_domid;
    info.gfn = _gfn(vuart_op->gfn);

    if ( d->creation_finished )
        return -EPERM;

    if ( vuart_op->type != XEN_DOMCTL_VUART_TYPE_VPL011 )
        return -EOPNOTSUPP;

    rc = domain_vpl011_init(d, &info);

    if ( !rc )
        vuart_op->evtchn = info.evtchn;

    return rc;
}

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

        return p2m_cache_flush(d, _gfn(s), domctl->u.cacheflush.nr_pfns);
    }
    case XEN_DOMCTL_bind_pt_irq:
    {
        int rc;
        struct xen_domctl_bind_pt_irq *bind = &domctl->u.bind_pt_irq;
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
        struct xen_domctl_bind_pt_irq *bind = &domctl->u.bind_pt_irq;
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

    case XEN_DOMCTL_disable_migrate:
        d->disable_migrate = domctl->u.disable_migrate.disable;
        return 0;

    case XEN_DOMCTL_vuart_op:
    {
        int rc;
        unsigned int i;
        struct xen_domctl_vuart_op *vuart_op = &domctl->u.vuart_op;

        /* check that structure padding must be 0. */
        for ( i = 0; i < sizeof(vuart_op->pad); i++ )
            if ( vuart_op->pad[i] )
                return -EINVAL;

        switch( vuart_op->cmd )
        {
        case XEN_DOMCTL_VUART_OP_INIT:
            rc = handle_vuart_init(d, vuart_op);
            break;

        default:
            rc = -EINVAL;
            break;
        }

        if ( !rc )
            rc = copy_to_guest(u_domctl, domctl, 1);

        return rc;
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
