/*
 *  This file contains the Flask hook function implementations for Xen.
 *
 *  Author:  George Coker, <gscoker@alpha.ncsc.mil>
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License version 2,
 *      as published by the Free Software Foundation.
 */

#include <xen/init.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/paging.h>
#include <xen/xmalloc.h>
#include <xsm/xsm.h>
#include <xen/spinlock.h>
#include <xen/cpumask.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/xenoprof.h>
#include <xen/iommu.h>
#ifdef CONFIG_HAS_PCI
#include <asm/msi.h>
#endif
#include <public/xen.h>
#include <public/physdev.h>
#include <public/platform.h>
#include <public/version.h>

#include <public/xsm/flask_op.h>

#include <avc.h>
#include <avc_ss.h>
#include <objsec.h>
#include <conditional.h>

static u32 domain_sid(const struct domain *dom)
{
    struct domain_security_struct *dsec = dom->ssid;
    return dsec->sid;
}

static u32 domain_target_sid(const struct domain *src,
                             const struct domain *dst)
{
    struct domain_security_struct *ssec = src->ssid;
    struct domain_security_struct *dsec = dst->ssid;
    if (src == dst)
        return ssec->self_sid;
    if (src->target == dst)
        return ssec->target_sid;
    return dsec->sid;
}

static u32 evtchn_sid(const struct evtchn *chn)
{
    return chn->ssid.flask_sid;
}

static int domain_has_perm(const struct domain *dom1,
                           const struct domain *dom2,
                           u16 class, u32 perms)
{
    u32 ssid, tsid;
    struct avc_audit_data ad;
    AVC_AUDIT_DATA_INIT(&ad, NONE);
    ad.sdom = dom1;
    ad.tdom = dom2;

    ssid = domain_sid(dom1);
    tsid = domain_target_sid(dom1, dom2);

    return avc_has_perm(ssid, tsid, class, perms, &ad);
}

static int avc_current_has_perm(u32 tsid, u16 class, u32 perm,
                                struct avc_audit_data *ad)
{
    u32 csid = domain_sid(current->domain);
    return avc_has_perm(csid, tsid, class, perm, ad);
}

static int current_has_perm(struct domain *d, u16 class, u32 perms)
{
    return domain_has_perm(current->domain, d, class, perms);
}

static int domain_has_evtchn(struct domain *d, struct evtchn *chn, u32 perms)
{
    u32 dsid = domain_sid(d);
    u32 esid = evtchn_sid(chn);

    return avc_has_perm(dsid, esid, SECCLASS_EVENT, perms, NULL);
}

static int domain_has_xen(struct domain *d, u32 perms)
{
    u32 dsid = domain_sid(d);

    return avc_has_perm(dsid, SECINITSID_XEN, SECCLASS_XEN, perms, NULL);
}

static int get_irq_sid(int irq, u32 *sid, struct avc_audit_data *ad)
{
    if ( irq >= nr_irqs || irq < 0 )
        return -EINVAL;
    if ( irq < nr_static_irqs ) {
        if (ad) {
            AVC_AUDIT_DATA_INIT(ad, IRQ);
            ad->irq = irq;
        }
        return security_irq_sid(irq, sid);
    }
#ifdef CONFIG_HAS_PCI
    {
        struct irq_desc *desc = irq_to_desc(irq);
        if ( desc->msi_desc && desc->msi_desc->dev ) {
            struct pci_dev *dev = desc->msi_desc->dev;
            u32 sbdf = (dev->seg << 16) | (dev->bus << 8) | dev->devfn;
            if (ad) {
                AVC_AUDIT_DATA_INIT(ad, DEV);
                ad->device = sbdf;
            }
            return security_device_sid(sbdf, sid);
        }
    }
#endif

    if (ad) {
        AVC_AUDIT_DATA_INIT(ad, IRQ);
        ad->irq = irq;
    }
    /* HPET or IOMMU IRQ, should not be seen by domains */
    *sid = SECINITSID_UNLABELED;
    return 0;
}

static int avc_unknown_permission(const char *name, int id)
{
    int rc;

    if ( !flask_enforcing || security_get_allow_unknown() )
    {
        printk(XENLOG_G_WARNING "FLASK: Allowing unknown %s: %d.\n", name, id);
        rc = 0;
    }
    else
    {
        printk(XENLOG_G_ERR "FLASK: Denying unknown %s: %d.\n", name, id);
        rc = -EPERM;
    }

    return rc;
}

static int flask_domain_alloc_security(struct domain *d)
{
    struct domain_security_struct *dsec;

    dsec = xzalloc(struct domain_security_struct);
    if ( !dsec )
        return -ENOMEM;

    switch ( d->domain_id )
    {
    case DOMID_IDLE:
        dsec->sid = SECINITSID_XEN;
        break;
    case DOMID_XEN:
        dsec->sid = SECINITSID_DOMXEN;
        break;
    case DOMID_IO:
        dsec->sid = SECINITSID_DOMIO;
        break;
    default:
        dsec->sid = SECINITSID_UNLABELED;
    }

    dsec->self_sid = dsec->sid;
    d->ssid = dsec;

    return 0;
}

static void flask_domain_free_security(struct domain *d)
{
    struct domain_security_struct *dsec = d->ssid;

    if ( !dsec )
        return;

    d->ssid = NULL;
    xfree(dsec);
}

static int flask_evtchn_unbound(struct domain *d1, struct evtchn *chn, 
                                domid_t id2)
{
    u32 sid1, sid2, newsid;
    int rc;
    struct domain *d2;

    d2 = rcu_lock_domain_by_any_id(id2);
    if ( d2 == NULL )
        return -EPERM;

    sid1 = domain_sid(d1);
    sid2 = domain_target_sid(d1, d2);

    rc = security_transition_sid(sid1, sid2, SECCLASS_EVENT, &newsid);
    if ( rc )
        goto out;

    rc = avc_current_has_perm(newsid, SECCLASS_EVENT, EVENT__CREATE, NULL);
    if ( rc )
        goto out;

    rc = avc_has_perm(newsid, sid2, SECCLASS_EVENT, EVENT__BIND, NULL);
    if ( rc )
        goto out;

    chn->ssid.flask_sid = newsid;

 out:
    rcu_unlock_domain(d2);
    return rc;
}

static int flask_evtchn_interdomain(struct domain *d1, struct evtchn *chn1, 
                                    struct domain *d2, struct evtchn *chn2)
{
    u32 sid1, sid2, newsid, reverse_sid;
    int rc;
    struct avc_audit_data ad;
    AVC_AUDIT_DATA_INIT(&ad, NONE);
    ad.sdom = d1;
    ad.tdom = d2;

    sid1 = domain_sid(d1);
    sid2 = domain_target_sid(d1, d2);

    rc = security_transition_sid(sid1, sid2, SECCLASS_EVENT, &newsid);
    if ( rc )
    {
        printk("security_transition_sid failed, rc=%d, Dom%d\n",
               -rc, d2->domain_id);
        return rc;
    }

    rc = avc_current_has_perm(newsid, SECCLASS_EVENT, EVENT__CREATE, &ad);
    if ( rc )
        return rc;

    rc = avc_has_perm(newsid, sid2, SECCLASS_EVENT, EVENT__BIND, &ad);
    if ( rc )
        return rc;

    /* It's possible the target domain has changed (relabel or destroy/create)
     * since the unbound part was created; re-validate this binding now.
     */
    reverse_sid = evtchn_sid(chn2);
    sid1 = domain_target_sid(d2, d1);
    rc = avc_has_perm(reverse_sid, sid1, SECCLASS_EVENT, EVENT__BIND, &ad);
    if ( rc )
        return rc;

    chn1->ssid.flask_sid = newsid;

    return rc;
}

static void flask_evtchn_close_post(struct evtchn *chn)
{
    chn->ssid.flask_sid = SECINITSID_UNLABELED;
}

static int flask_evtchn_send(struct domain *d, struct evtchn *chn)
{
    int rc;

    switch ( chn->state )
    {
    case ECS_INTERDOMAIN:
        rc = domain_has_evtchn(d, chn, EVENT__SEND);
        break;
    case ECS_IPI:
    case ECS_UNBOUND:
        rc = 0;
        break;
    default:
        rc = avc_unknown_permission("event channel state", chn->state);
    }

    return rc;
}

static int flask_evtchn_status(struct domain *d, struct evtchn *chn)
{
    return domain_has_evtchn(d, chn, EVENT__STATUS);
}

static int flask_evtchn_reset(struct domain *d1, struct domain *d2)
{
    return domain_has_perm(d1, d2, SECCLASS_EVENT, EVENT__RESET);
}

static int flask_alloc_security_evtchn(struct evtchn *chn)
{
    chn->ssid.flask_sid = SECINITSID_UNLABELED;

    return 0;    
}

static void flask_free_security_evtchn(struct evtchn *chn)
{
    if ( !chn )
        return;

    chn->ssid.flask_sid = SECINITSID_UNLABELED;
}

static char *flask_show_security_evtchn(struct domain *d, const struct evtchn *chn)
{
    int irq;
    u32 sid = 0;
    char *ctx;
    u32 ctx_len;

    switch ( chn->state )
    {
    case ECS_UNBOUND:
    case ECS_INTERDOMAIN:
        sid = evtchn_sid(chn);
        break;
    case ECS_PIRQ:
        irq = domain_pirq_to_irq(d, chn->u.pirq.irq);
        if (irq && get_irq_sid(irq, &sid, NULL))
            return NULL;
        break;
    }
    if ( !sid )
        return NULL;
    if (security_sid_to_context(sid, &ctx, &ctx_len))
        return NULL;
    return ctx;
}

static int flask_init_hardware_domain(struct domain *d)
{
    return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__CREATE_HARDWARE_DOMAIN);
}

static int flask_grant_mapref(struct domain *d1, struct domain *d2, 
                              uint32_t flags)
{
    u32 perms = GRANT__MAP_READ;

    if ( !(flags & GNTMAP_readonly) )
        perms |= GRANT__MAP_WRITE;

    return domain_has_perm(d1, d2, SECCLASS_GRANT, perms);
}

static int flask_grant_unmapref(struct domain *d1, struct domain *d2)
{
    return domain_has_perm(d1, d2, SECCLASS_GRANT, GRANT__UNMAP);
}

static int flask_grant_setup(struct domain *d1, struct domain *d2)
{
    return domain_has_perm(d1, d2, SECCLASS_GRANT, GRANT__SETUP);
}

static int flask_grant_transfer(struct domain *d1, struct domain *d2)
{
    return domain_has_perm(d1, d2, SECCLASS_GRANT, GRANT__TRANSFER);
}

static int flask_grant_copy(struct domain *d1, struct domain *d2)
{
    return domain_has_perm(d1, d2, SECCLASS_GRANT, GRANT__COPY);
}

static int flask_grant_query_size(struct domain *d1, struct domain *d2)
{
    return domain_has_perm(d1, d2, SECCLASS_GRANT, GRANT__QUERY);
}

static int flask_get_pod_target(struct domain *d)
{
    return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__GETPODTARGET);
}

static int flask_set_pod_target(struct domain *d)
{
    return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__SETPODTARGET);
}

static int flask_memory_exchange(struct domain *d)
{
    return current_has_perm(d, SECCLASS_MMU, MMU__EXCHANGE);
}

static int flask_memory_adjust_reservation(struct domain *d1, struct domain *d2)
{
    return domain_has_perm(d1, d2, SECCLASS_MMU, MMU__ADJUST);
}

static int flask_memory_stat_reservation(struct domain *d1, struct domain *d2)
{
    return domain_has_perm(d1, d2, SECCLASS_MMU, MMU__STAT);
}

static int flask_memory_pin_page(struct domain *d1, struct domain *d2,
                                 struct page_info *page)
{
    return domain_has_perm(d1, d2, SECCLASS_MMU, MMU__PINPAGE);
}

static int flask_claim_pages(struct domain *d)
{
    return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__SETCLAIM);
}

static int flask_get_vnumainfo(struct domain *d)
{
    return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__GET_VNUMAINFO);
}

static int flask_console_io(struct domain *d, int cmd)
{
    u32 perm;

    switch ( cmd )
    {
    case CONSOLEIO_read:
        perm = XEN__READCONSOLE;
        break;
    case CONSOLEIO_write:
        perm = XEN__WRITECONSOLE;
        break;
    default:
        return avc_unknown_permission("console_io", cmd);
    }

    return domain_has_xen(d, perm);
}

static int flask_profile(struct domain *d, int op)
{
    u32 perm;

    switch ( op )
    {
    case XENOPROF_init:
    case XENOPROF_enable_virq:
    case XENOPROF_disable_virq:
    case XENOPROF_get_buffer:
        perm = XEN__NONPRIVPROFILE;
        break;
    case XENOPROF_reset_active_list:
    case XENOPROF_reset_passive_list:
    case XENOPROF_set_active:
    case XENOPROF_set_passive:
    case XENOPROF_reserve_counters:
    case XENOPROF_counter:
    case XENOPROF_setup_events:
    case XENOPROF_start:
    case XENOPROF_stop:
    case XENOPROF_release_counters:
    case XENOPROF_shutdown:
        perm = XEN__PRIVPROFILE;
        break;
    default:
        return avc_unknown_permission("xenoprof op", op);
    }

    return domain_has_xen(d, perm);
}

static int flask_kexec(void)
{
    return domain_has_xen(current->domain, XEN__KEXEC);
}

static int flask_schedop_shutdown(struct domain *d1, struct domain *d2)
{
    return domain_has_perm(d1, d2, SECCLASS_DOMAIN, DOMAIN__SHUTDOWN);
}

static void flask_security_domaininfo(struct domain *d, 
                                      struct xen_domctl_getdomaininfo *info)
{
    info->ssidref = domain_sid(d);
}

static int flask_domain_create(struct domain *d, u32 ssidref)
{
    int rc;
    struct domain_security_struct *dsec = d->ssid;
    static int dom0_created = 0;

    if ( is_idle_domain(current->domain) && !dom0_created )
    {
        dsec->sid = SECINITSID_DOM0;
        dom0_created = 1;
    }
    else
    {
        rc = avc_current_has_perm(ssidref, SECCLASS_DOMAIN,
                          DOMAIN__CREATE, NULL);
        if ( rc )
            return rc;

        dsec->sid = ssidref;
    }
    dsec->self_sid = dsec->sid;

    rc = security_transition_sid(dsec->sid, dsec->sid, SECCLASS_DOMAIN,
                                 &dsec->self_sid);

    return rc;
}

static int flask_getdomaininfo(struct domain *d)
{
    return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__GETDOMAININFO);
}

static int flask_domctl_scheduler_op(struct domain *d, int op)
{
    switch ( op )
    {
    case XEN_DOMCTL_SCHEDOP_putinfo:
    case XEN_DOMCTL_SCHEDOP_putvcpuinfo:
        return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__SETSCHEDULER);

    case XEN_DOMCTL_SCHEDOP_getinfo:
    case XEN_DOMCTL_SCHEDOP_getvcpuinfo:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__GETSCHEDULER);

    default:
        return avc_unknown_permission("domctl_scheduler_op", op);
    }
}

static int flask_sysctl_scheduler_op(int op)
{
    switch ( op )
    {
    case XEN_SYSCTL_SCHEDOP_putinfo:
        return domain_has_xen(current->domain, XEN__SETSCHEDULER);

    case XEN_SYSCTL_SCHEDOP_getinfo:
        return domain_has_xen(current->domain, XEN__GETSCHEDULER);

    default:
        return avc_unknown_permission("sysctl_scheduler_op", op);
    }
}

static int flask_set_target(struct domain *d, struct domain *t)
{
    int rc;
    struct domain_security_struct *dsec, *tsec;
    dsec = d->ssid;
    tsec = t->ssid;

    rc = current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__MAKE_PRIV_FOR);
    if ( rc )
        return rc;
    rc = current_has_perm(t, SECCLASS_DOMAIN2, DOMAIN2__SET_AS_TARGET);
    if ( rc )
        return rc;
    /* Use avc_has_perm to avoid resolving target/current SID */
    rc = avc_has_perm(dsec->sid, tsec->sid, SECCLASS_DOMAIN, DOMAIN__SET_TARGET, NULL);
    if ( rc )
        return rc;

    /* (tsec, dsec) defaults the label to tsec, as it should here */
    rc = security_transition_sid(tsec->sid, dsec->sid, SECCLASS_DOMAIN,
                                 &dsec->target_sid);
    return rc;
}

static int flask_domctl(struct domain *d, int cmd)
{
    switch ( cmd )
    {
    /* These have individual XSM hooks (common/domctl.c) */
    case XEN_DOMCTL_createdomain:
    case XEN_DOMCTL_getdomaininfo:
    case XEN_DOMCTL_scheduler_op:
    case XEN_DOMCTL_irq_permission:
    case XEN_DOMCTL_iomem_permission:
    case XEN_DOMCTL_memory_mapping:
    case XEN_DOMCTL_set_target:
    case XEN_DOMCTL_vm_event_op:

    /* These have individual XSM hooks (arch/../domctl.c) */
    case XEN_DOMCTL_bind_pt_irq:
    case XEN_DOMCTL_unbind_pt_irq:
#ifdef CONFIG_X86
    /* These have individual XSM hooks (arch/x86/domctl.c) */
    case XEN_DOMCTL_shadow_op:
    case XEN_DOMCTL_ioport_permission:
    case XEN_DOMCTL_ioport_mapping:
#endif
#ifdef CONFIG_HAS_PASSTHROUGH
    /*
     * These have individual XSM hooks
     * (drivers/passthrough/{pci,device_tree.c)
     */
    case XEN_DOMCTL_get_device_group:
    case XEN_DOMCTL_test_assign_device:
    case XEN_DOMCTL_assign_device:
    case XEN_DOMCTL_deassign_device:
#endif
        return 0;

    case XEN_DOMCTL_destroydomain:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__DESTROY);

    case XEN_DOMCTL_pausedomain:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__PAUSE);

    case XEN_DOMCTL_unpausedomain:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__UNPAUSE);

    case XEN_DOMCTL_setvcpuaffinity:
    case XEN_DOMCTL_setnodeaffinity:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__SETAFFINITY);

    case XEN_DOMCTL_getvcpuaffinity:
    case XEN_DOMCTL_getnodeaffinity:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__GETAFFINITY);

    case XEN_DOMCTL_resumedomain:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__RESUME);

    case XEN_DOMCTL_max_vcpus:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__MAX_VCPUS);

    case XEN_DOMCTL_max_mem:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__SETDOMAINMAXMEM);

    case XEN_DOMCTL_setdomainhandle:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__SETDOMAINHANDLE);

    case XEN_DOMCTL_set_ext_vcpucontext:
    case XEN_DOMCTL_set_vcpu_msrs:
    case XEN_DOMCTL_setvcpucontext:
    case XEN_DOMCTL_setvcpuextstate:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__SETVCPUCONTEXT);

    case XEN_DOMCTL_get_ext_vcpucontext:
    case XEN_DOMCTL_get_vcpu_msrs:
    case XEN_DOMCTL_getvcpucontext:
    case XEN_DOMCTL_getvcpuextstate:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__GETVCPUCONTEXT);

    case XEN_DOMCTL_getvcpuinfo:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__GETVCPUINFO);

    case XEN_DOMCTL_settimeoffset:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__SETTIME);

    case XEN_DOMCTL_setdebugging:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__SETDEBUGGING);

    case XEN_DOMCTL_getpageframeinfo3:
        return current_has_perm(d, SECCLASS_MMU, MMU__PAGEINFO);

    case XEN_DOMCTL_hypercall_init:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__HYPERCALL);

    case XEN_DOMCTL_sethvmcontext:
        return current_has_perm(d, SECCLASS_HVM, HVM__SETHVMC);

    case XEN_DOMCTL_gethvmcontext:
    case XEN_DOMCTL_gethvmcontext_partial:
        return current_has_perm(d, SECCLASS_HVM, HVM__GETHVMC);

    case XEN_DOMCTL_set_address_size:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__SETADDRSIZE);

    case XEN_DOMCTL_get_address_size:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__GETADDRSIZE);

    case XEN_DOMCTL_mem_sharing_op:
        return current_has_perm(d, SECCLASS_HVM, HVM__MEM_SHARING);

    case XEN_DOMCTL_sendtrigger:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__TRIGGER);

    case XEN_DOMCTL_set_access_required:
        return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__VM_EVENT);

    case XEN_DOMCTL_monitor_op:
        return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__VM_EVENT);

    case XEN_DOMCTL_debug_op:
    case XEN_DOMCTL_gdbsx_guestmemio:
    case XEN_DOMCTL_gdbsx_pausevcpu:
    case XEN_DOMCTL_gdbsx_unpausevcpu:
    case XEN_DOMCTL_gdbsx_domstatus:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__SETDEBUGGING);

    case XEN_DOMCTL_subscribe:
    case XEN_DOMCTL_disable_migrate:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__SET_MISC_INFO);

    case XEN_DOMCTL_set_virq_handler:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN__SET_VIRQ_HANDLER);

    case XEN_DOMCTL_set_cpuid:
        return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__SET_CPUID);

    case XEN_DOMCTL_gettscinfo:
        return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__GETTSC);

    case XEN_DOMCTL_settscinfo:
        return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__SETTSC);

    case XEN_DOMCTL_audit_p2m:
        return current_has_perm(d, SECCLASS_HVM, HVM__AUDIT_P2M);

    case XEN_DOMCTL_cacheflush:
        return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__CACHEFLUSH);

    case XEN_DOMCTL_setvnumainfo:
        return current_has_perm(d, SECCLASS_DOMAIN, DOMAIN2__SET_VNUMAINFO);
    case XEN_DOMCTL_psr_cmt_op:
        return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__PSR_CMT_OP);

    case XEN_DOMCTL_psr_alloc:
        return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__PSR_ALLOC);

    case XEN_DOMCTL_soft_reset:
        return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__SOFT_RESET);

    case XEN_DOMCTL_get_cpu_policy:
        return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__GET_CPU_POLICY);

    default:
        return avc_unknown_permission("domctl", cmd);
    }
}

static int flask_sysctl(int cmd)
{
    switch ( cmd )
    {
    /* These have individual XSM hooks */
    case XEN_SYSCTL_readconsole:
    case XEN_SYSCTL_getdomaininfolist:
    case XEN_SYSCTL_page_offline_op:
    case XEN_SYSCTL_scheduler_op:
#ifdef CONFIG_X86
    case XEN_SYSCTL_cpu_hotplug:
#endif
        return 0;

    case XEN_SYSCTL_tbuf_op:
        return domain_has_xen(current->domain, XEN__TBUFCONTROL);

    case XEN_SYSCTL_sched_id:
        return domain_has_xen(current->domain, XEN__GETSCHEDULER);

    case XEN_SYSCTL_perfc_op:
        return domain_has_xen(current->domain, XEN__PERFCONTROL);

    case XEN_SYSCTL_debug_keys:
        return domain_has_xen(current->domain, XEN__DEBUG);

    case XEN_SYSCTL_getcpuinfo:
        return domain_has_xen(current->domain, XEN__GETCPUINFO);

    case XEN_SYSCTL_availheap:
        return domain_has_xen(current->domain, XEN__HEAP);

    case XEN_SYSCTL_get_pmstat:
        return domain_has_xen(current->domain, XEN__PM_OP);

    case XEN_SYSCTL_pm_op:
        return domain_has_xen(current->domain, XEN__PM_OP);

    case XEN_SYSCTL_lockprof_op:
        return domain_has_xen(current->domain, XEN__LOCKPROF);

    case XEN_SYSCTL_cpupool_op:
        return domain_has_xen(current->domain, XEN__CPUPOOL_OP);

    case XEN_SYSCTL_physinfo:
    case XEN_SYSCTL_cputopoinfo:
    case XEN_SYSCTL_numainfo:
    case XEN_SYSCTL_pcitopoinfo:
    case XEN_SYSCTL_get_cpu_policy:
        return domain_has_xen(current->domain, XEN__PHYSINFO);

    case XEN_SYSCTL_psr_cmt_op:
        return avc_current_has_perm(SECINITSID_XEN, SECCLASS_XEN2,
                                    XEN2__PSR_CMT_OP, NULL);
    case XEN_SYSCTL_psr_alloc:
        return avc_current_has_perm(SECINITSID_XEN, SECCLASS_XEN2,
                                    XEN2__PSR_ALLOC, NULL);

    case XEN_SYSCTL_get_cpu_levelling_caps:
        return avc_current_has_perm(SECINITSID_XEN, SECCLASS_XEN2,
                                    XEN2__GET_CPU_LEVELLING_CAPS, NULL);

    case XEN_SYSCTL_get_cpu_featureset:
        return avc_current_has_perm(SECINITSID_XEN, SECCLASS_XEN2,
                                    XEN2__GET_CPU_FEATURESET, NULL);

    case XEN_SYSCTL_livepatch_op:
        return avc_current_has_perm(SECINITSID_XEN, SECCLASS_XEN2,
                                    XEN2__LIVEPATCH_OP, NULL);
    case XEN_SYSCTL_coverage_op:
        return avc_current_has_perm(SECINITSID_XEN, SECCLASS_XEN2,
                                    XEN2__COVERAGE_OP, NULL);
    case XEN_SYSCTL_set_parameter:
        return avc_current_has_perm(SECINITSID_XEN, SECCLASS_XEN2,
                                    XEN2__SET_PARAMETER, NULL);

    default:
        return avc_unknown_permission("sysctl", cmd);
    }
}

static int flask_readconsole(uint32_t clear)
{
    u32 perms = XEN__READCONSOLE;

    if ( clear )
        perms |= XEN__CLEARCONSOLE;

    return domain_has_xen(current->domain, perms);
}

static inline u32 resource_to_perm(uint8_t access)
{
    if ( access )
        return RESOURCE__ADD;
    else
        return RESOURCE__REMOVE;
}

static char *flask_show_irq_sid (int irq)
{
    u32 sid, ctx_len;
    char *ctx;
    int rc = get_irq_sid(irq, &sid, NULL);
    if ( rc )
        return NULL;

    if (security_sid_to_context(sid, &ctx, &ctx_len))
        return NULL;

    return ctx;
}

static int flask_map_domain_pirq (struct domain *d)
{
    return current_has_perm(d, SECCLASS_RESOURCE, RESOURCE__ADD);
}

static int flask_map_domain_msi (struct domain *d, int irq, const void *data,
                                 u32 *sid, struct avc_audit_data *ad)
{
#ifdef CONFIG_HAS_PCI
    const struct msi_info *msi = data;
    u32 machine_bdf = (msi->seg << 16) | (msi->bus << 8) | msi->devfn;

    AVC_AUDIT_DATA_INIT(ad, DEV);
    ad->device = machine_bdf;

    return security_device_sid(machine_bdf, sid);
#else
    return -EINVAL;
#endif
}

static u32 flask_iommu_resource_use_perm(const struct domain *d)
{
    /* Obtain the permission level required for allowing a domain
     * to use an assigned device.
     *
     * An active IOMMU with interrupt remapping capability is essential
     * for ensuring strict isolation of devices, so provide a distinct
     * permission for that case and also enable optional support for
     * less capable hardware (no IOMMU or IOMMU missing intremap capability)
     * via other separate permissions.
     */
    u32 perm = RESOURCE__USE_NOIOMMU;

    if ( is_iommu_enabled(d) )
        perm = ( iommu_intremap ? RESOURCE__USE_IOMMU :
                                  RESOURCE__USE_IOMMU_NOINTREMAP );
    return perm;
}

static int flask_map_domain_irq (struct domain *d, int irq, const void *data)
{
    u32 sid, dsid;
    int rc = -EPERM;
    struct avc_audit_data ad;
    u32 dperm = flask_iommu_resource_use_perm(d);

    if ( irq >= nr_static_irqs && data ) {
        rc = flask_map_domain_msi(d, irq, data, &sid, &ad);
    } else {
        rc = get_irq_sid(irq, &sid, &ad);
    }

    if ( rc )
        return rc;

    dsid = domain_sid(d);

    rc = avc_current_has_perm(sid, SECCLASS_RESOURCE, RESOURCE__ADD_IRQ, &ad);
    if ( rc )
        return rc;

    rc = avc_has_perm(dsid, sid, SECCLASS_RESOURCE, dperm, &ad);
    return rc;
}

static int flask_unmap_domain_pirq (struct domain *d)
{
    return current_has_perm(d, SECCLASS_RESOURCE, RESOURCE__REMOVE);
}

static int flask_unmap_domain_msi (struct domain *d, int irq, const void *data,
                                   u32 *sid, struct avc_audit_data *ad)
{
#ifdef CONFIG_HAS_PCI
    const struct pci_dev *pdev = data;
    u32 machine_bdf = (pdev->seg << 16) | (pdev->bus << 8) | pdev->devfn;

    AVC_AUDIT_DATA_INIT(ad, DEV);
    ad->device = machine_bdf;

    return security_device_sid(machine_bdf, sid);
#else
    return -EINVAL;
#endif
}

static int flask_unmap_domain_irq (struct domain *d, int irq, const void *data)
{
    u32 sid;
    int rc = -EPERM;
    struct avc_audit_data ad;

    if ( irq >= nr_static_irqs && data ) {
        rc = flask_unmap_domain_msi(d, irq, data, &sid, &ad);
    } else {
        rc = get_irq_sid(irq, &sid, &ad);
    }
    if ( rc )
        return rc;

    rc = avc_current_has_perm(sid, SECCLASS_RESOURCE, RESOURCE__REMOVE_IRQ, &ad);
    return rc;
}

static int flask_bind_pt_irq (struct domain *d, struct xen_domctl_bind_pt_irq *bind)
{
    u32 dsid, rsid;
    int rc = -EPERM;
    int irq;
    struct avc_audit_data ad;
    u32 dperm = flask_iommu_resource_use_perm(d);

    rc = current_has_perm(d, SECCLASS_RESOURCE, RESOURCE__ADD);
    if ( rc )
        return rc;

    irq = domain_pirq_to_irq(d, bind->machine_irq);

    rc = get_irq_sid(irq, &rsid, &ad);
    if ( rc )
        return rc;

    rc = avc_current_has_perm(rsid, SECCLASS_HVM, HVM__BIND_IRQ, &ad);
    if ( rc )
        return rc;

    dsid = domain_sid(d);
    return avc_has_perm(dsid, rsid, SECCLASS_RESOURCE, dperm, &ad);
}

static int flask_unbind_pt_irq (struct domain *d, struct xen_domctl_bind_pt_irq *bind)
{
    return current_has_perm(d, SECCLASS_RESOURCE, RESOURCE__REMOVE);
}

static int flask_irq_permission (struct domain *d, int pirq, uint8_t access)
{
    /* the PIRQ number is not useful; real IRQ is checked during mapping */
    return current_has_perm(d, SECCLASS_RESOURCE, resource_to_perm(access));
}

struct iomem_has_perm_data {
    u32 ssid;
    u32 dsid;
    u32 perm;
    u32 use_perm;
};

static int _iomem_has_perm(void *v, u32 sid, unsigned long start, unsigned long end)
{
    struct iomem_has_perm_data *data = v;
    struct avc_audit_data ad;
    int rc = -EPERM;

    AVC_AUDIT_DATA_INIT(&ad, RANGE);
    ad.range.start = start;
    ad.range.end = end;

    rc = avc_has_perm(data->ssid, sid, SECCLASS_RESOURCE, data->perm, &ad);

    if ( rc )
        return rc;

    return avc_has_perm(data->dsid, sid, SECCLASS_RESOURCE, data->use_perm, &ad);
}

static int flask_iomem_permission(struct domain *d, uint64_t start, uint64_t end, uint8_t access)
{
    struct iomem_has_perm_data data;
    int rc;

    rc = current_has_perm(d, SECCLASS_RESOURCE,
                         resource_to_perm(access));
    if ( rc )
        return rc;

    if ( access )
        data.perm = RESOURCE__ADD_IOMEM;
    else
        data.perm = RESOURCE__REMOVE_IOMEM;

    data.ssid = domain_sid(current->domain);
    data.dsid = domain_sid(d);
    data.use_perm = flask_iommu_resource_use_perm(d);

    return security_iterate_iomem_sids(start, end, _iomem_has_perm, &data);
}

static int flask_iomem_mapping(struct domain *d, uint64_t start, uint64_t end, uint8_t access)
{
    return flask_iomem_permission(d, start, end, access);
}

static int flask_pci_config_permission(struct domain *d, uint32_t machine_bdf, uint16_t start, uint16_t end, uint8_t access)
{
    u32 dsid, rsid;
    int rc = -EPERM;
    struct avc_audit_data ad;
    u32 perm;

    rc = security_device_sid(machine_bdf, &rsid);
    if ( rc )
        return rc;

    /* Writes to the BARs count as setup */
    if ( access && (end >= 0x10 && start < 0x28) )
        perm = RESOURCE__SETUP;
    else
        perm = flask_iommu_resource_use_perm(d);

    AVC_AUDIT_DATA_INIT(&ad, DEV);
    ad.device = (unsigned long) machine_bdf;
    dsid = domain_sid(d);
    return avc_has_perm(dsid, rsid, SECCLASS_RESOURCE, perm, &ad);

}

static int flask_resource_plug_core(void)
{
    return avc_current_has_perm(SECINITSID_DOMXEN, SECCLASS_RESOURCE, RESOURCE__PLUG, NULL);
}

static int flask_resource_unplug_core(void)
{
    return avc_current_has_perm(SECINITSID_DOMXEN, SECCLASS_RESOURCE, RESOURCE__UNPLUG, NULL);
}

static int flask_resource_use_core(void)
{
    return avc_current_has_perm(SECINITSID_DOMXEN, SECCLASS_RESOURCE, RESOURCE__USE, NULL);
}

static int flask_resource_plug_pci(uint32_t machine_bdf)
{
    u32 rsid;
    int rc = -EPERM;
    struct avc_audit_data ad;

    rc = security_device_sid(machine_bdf, &rsid);
    if ( rc )
        return rc;

    AVC_AUDIT_DATA_INIT(&ad, DEV);
    ad.device = (unsigned long) machine_bdf;
    return avc_current_has_perm(rsid, SECCLASS_RESOURCE, RESOURCE__PLUG, &ad);
}

static int flask_resource_unplug_pci(uint32_t machine_bdf)
{
    u32 rsid;
    int rc = -EPERM;
    struct avc_audit_data ad;

    rc = security_device_sid(machine_bdf, &rsid);
    if ( rc )
        return rc;

    AVC_AUDIT_DATA_INIT(&ad, DEV);
    ad.device = (unsigned long) machine_bdf;
    return avc_current_has_perm(rsid, SECCLASS_RESOURCE, RESOURCE__UNPLUG, &ad);
}

static int flask_resource_setup_pci(uint32_t machine_bdf)
{
    u32 rsid;
    int rc = -EPERM;
    struct avc_audit_data ad;

    rc = security_device_sid(machine_bdf, &rsid);
    if ( rc )
        return rc;

    AVC_AUDIT_DATA_INIT(&ad, DEV);
    ad.device = (unsigned long) machine_bdf;
    return avc_current_has_perm(rsid, SECCLASS_RESOURCE, RESOURCE__SETUP, &ad);
}

static int flask_resource_setup_gsi(int gsi)
{
    u32 rsid;
    int rc = -EPERM;
    struct avc_audit_data ad;

    rc = get_irq_sid(gsi, &rsid, &ad);
    if ( rc )
        return rc;

    return avc_current_has_perm(rsid, SECCLASS_RESOURCE, RESOURCE__SETUP, &ad);
}

static int flask_resource_setup_misc(void)
{
    return avc_current_has_perm(SECINITSID_XEN, SECCLASS_RESOURCE, RESOURCE__SETUP, NULL);
}

static inline int flask_page_offline(uint32_t cmd)
{
    switch (cmd) {
    case sysctl_page_offline:
        return flask_resource_unplug_core();
    case sysctl_page_online:
        return flask_resource_plug_core();
    case sysctl_query_page_offline:
        return flask_resource_use_core();
    default:
        return avc_unknown_permission("page_offline", cmd);
    }
}

static int flask_add_to_physmap(struct domain *d1, struct domain *d2)
{
    return domain_has_perm(d1, d2, SECCLASS_MMU, MMU__PHYSMAP);
}

static int flask_remove_from_physmap(struct domain *d1, struct domain *d2)
{
    return domain_has_perm(d1, d2, SECCLASS_MMU, MMU__PHYSMAP);
}

static int flask_map_gmfn_foreign(struct domain *d, struct domain *t)
{
    return domain_has_perm(d, t, SECCLASS_MMU, MMU__MAP_READ | MMU__MAP_WRITE);
}

static int flask_hvm_param(struct domain *d, unsigned long op)
{
    u32 perm;

    switch ( op )
    {
    case HVMOP_set_param:
        perm = HVM__SETPARAM;
        break;
    case HVMOP_get_param:
        perm = HVM__GETPARAM;
        break;
    default:
        perm = HVM__HVMCTL;
    }

    return current_has_perm(d, SECCLASS_HVM, perm);
}

static int flask_hvm_param_nested(struct domain *d)
{
    return current_has_perm(d, SECCLASS_HVM, HVM__NESTED);
}

static int flask_hvm_param_altp2mhvm(struct domain *d)
{
    return current_has_perm(d, SECCLASS_HVM, HVM__ALTP2MHVM);
}

static int flask_hvm_altp2mhvm_op(struct domain *d, uint64_t mode, uint32_t op)
{
    /*
     * Require both mode and XSM to allow the operation. Assume XSM rules
     * are written with the XSM_TARGET policy in mind, so add restrictions
     * on the domain acting on itself when forbidden by the mode.
     */
    switch ( mode )
    {
    case XEN_ALTP2M_mixed:
        break;
    case XEN_ALTP2M_limited:
        if ( HVMOP_altp2m_vcpu_enable_notify == op )
            break;
        /* fall-through */
    case XEN_ALTP2M_external:
        if ( d == current->domain )
            return -EPERM;
        break;
    };

    return current_has_perm(d, SECCLASS_HVM, HVM__ALTP2MHVM_OP);
}

static int flask_vm_event_control(struct domain *d, int mode, int op)
{
    return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__VM_EVENT);
}

#ifdef CONFIG_MEM_ACCESS
static int flask_mem_access(struct domain *d)
{
    return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__MEM_ACCESS);
}
#endif

#ifdef CONFIG_HAS_MEM_PAGING
static int flask_mem_paging(struct domain *d)
{
    return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__MEM_PAGING);
}
#endif

#ifdef CONFIG_MEM_SHARING
static int flask_mem_sharing(struct domain *d)
{
    return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__MEM_SHARING);
}
#endif

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_PCI)
static int flask_get_device_group(uint32_t machine_bdf)
{
    u32 rsid;
    int rc = -EPERM;

    rc = security_device_sid(machine_bdf, &rsid);
    if ( rc )
        return rc;

    return avc_current_has_perm(rsid, SECCLASS_RESOURCE, RESOURCE__STAT_DEVICE, NULL);
}

static int flask_test_assign_device(uint32_t machine_bdf)
{
    u32 rsid;
    int rc = -EPERM;

    rc = security_device_sid(machine_bdf, &rsid);
    if ( rc )
        return rc;

    return avc_current_has_perm(rsid, SECCLASS_RESOURCE, RESOURCE__STAT_DEVICE, NULL);
}

static int flask_assign_device(struct domain *d, uint32_t machine_bdf)
{
    u32 dsid, rsid;
    int rc = -EPERM;
    struct avc_audit_data ad;
    u32 dperm = flask_iommu_resource_use_perm(d);

    if ( !d )
        return flask_test_assign_device(machine_bdf);

    rc = current_has_perm(d, SECCLASS_RESOURCE, RESOURCE__ADD);
    if ( rc )
        return rc;

    rc = security_device_sid(machine_bdf, &rsid);
    if ( rc )
        return rc;

    AVC_AUDIT_DATA_INIT(&ad, DEV);
    ad.device = (unsigned long) machine_bdf;
    rc = avc_current_has_perm(rsid, SECCLASS_RESOURCE, RESOURCE__ADD_DEVICE, &ad);
    if ( rc )
        return rc;

    dsid = domain_sid(d);
    return avc_has_perm(dsid, rsid, SECCLASS_RESOURCE, dperm, &ad);
}

static int flask_deassign_device(struct domain *d, uint32_t machine_bdf)
{
    u32 rsid;
    int rc = -EPERM;

    rc = current_has_perm(d, SECCLASS_RESOURCE, RESOURCE__REMOVE);
    if ( rc )
        return rc;

    rc = security_device_sid(machine_bdf, &rsid);
    if ( rc )
        return rc;

    return avc_current_has_perm(rsid, SECCLASS_RESOURCE, RESOURCE__REMOVE_DEVICE, NULL);
}
#endif /* HAS_PASSTHROUGH && HAS_PCI */

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_DEVICE_TREE)
static int flask_test_assign_dtdevice(const char *dtpath)
{
    u32 rsid;
    int rc = -EPERM;

    rc = security_devicetree_sid(dtpath, &rsid);
    if ( rc )
        return rc;

    return avc_current_has_perm(rsid, SECCLASS_RESOURCE, RESOURCE__STAT_DEVICE,
                                NULL);
}

static int flask_assign_dtdevice(struct domain *d, const char *dtpath)
{
    u32 dsid, rsid;
    int rc = -EPERM;
    struct avc_audit_data ad;
    u32 dperm = flask_iommu_resource_use_perm(d);

    if ( !d )
        return flask_test_assign_dtdevice(dtpath);

    rc = current_has_perm(d, SECCLASS_RESOURCE, RESOURCE__ADD);
    if ( rc )
        return rc;

    rc = security_devicetree_sid(dtpath, &rsid);
    if ( rc )
        return rc;

    AVC_AUDIT_DATA_INIT(&ad, DTDEV);
    ad.dtdev = dtpath;
    rc = avc_current_has_perm(rsid, SECCLASS_RESOURCE, RESOURCE__ADD_DEVICE, &ad);
    if ( rc )
        return rc;

    dsid = domain_sid(d);
    return avc_has_perm(dsid, rsid, SECCLASS_RESOURCE, dperm, &ad);
}

static int flask_deassign_dtdevice(struct domain *d, const char *dtpath)
{
    u32 rsid;
    int rc = -EPERM;

    rc = current_has_perm(d, SECCLASS_RESOURCE, RESOURCE__REMOVE);
    if ( rc )
        return rc;

    rc = security_devicetree_sid(dtpath, &rsid);
    if ( rc )
        return rc;

    return avc_current_has_perm(rsid, SECCLASS_RESOURCE, RESOURCE__REMOVE_DEVICE,
                                NULL);
}
#endif /* HAS_PASSTHROUGH && HAS_DEVICE_TREE */

static int flask_platform_op(uint32_t op)
{
    switch ( op )
    {
#ifdef CONFIG_X86
    /* These operations have their own XSM hooks */
    case XENPF_cpu_online:
    case XENPF_cpu_offline:
    case XENPF_cpu_hotadd:
    case XENPF_mem_hotadd:
        return 0;
#endif

    case XENPF_settime32:
    case XENPF_settime64:
        return domain_has_xen(current->domain, XEN__SETTIME);

    case XENPF_add_memtype:
        return domain_has_xen(current->domain, XEN__MTRR_ADD);

    case XENPF_del_memtype:
        return domain_has_xen(current->domain, XEN__MTRR_DEL);

    case XENPF_read_memtype:
        return domain_has_xen(current->domain, XEN__MTRR_READ);

    case XENPF_microcode_update:
        return domain_has_xen(current->domain, XEN__MICROCODE);

    case XENPF_platform_quirk:
        return domain_has_xen(current->domain, XEN__QUIRK);

    case XENPF_firmware_info:
        return domain_has_xen(current->domain, XEN__FIRMWARE);

    case XENPF_efi_runtime_call:
        return domain_has_xen(current->domain, XEN__FIRMWARE);

    case XENPF_enter_acpi_sleep:
        return domain_has_xen(current->domain, XEN__SLEEP);

    case XENPF_change_freq:
        return domain_has_xen(current->domain, XEN__FREQUENCY);

    case XENPF_getidletime:
        return domain_has_xen(current->domain, XEN__GETIDLE);

    case XENPF_set_processor_pminfo:
    case XENPF_core_parking:
        return domain_has_xen(current->domain, XEN__PM_OP);

    case XENPF_get_cpu_version:
    case XENPF_get_cpuinfo:
        return domain_has_xen(current->domain, XEN__GETCPUINFO);

    case XENPF_resource_op:
        return avc_current_has_perm(SECINITSID_XEN, SECCLASS_XEN2,
                                    XEN2__RESOURCE_OP, NULL);

    case XENPF_get_symbol:
        return avc_has_perm(domain_sid(current->domain), SECINITSID_XEN,
                            SECCLASS_XEN2, XEN2__GET_SYMBOL, NULL);

    default:
        return avc_unknown_permission("platform_op", op);
    }
}

#ifdef CONFIG_X86
static int flask_do_mca(void)
{
    return domain_has_xen(current->domain, XEN__MCA_OP);
}

static int flask_shadow_control(struct domain *d, uint32_t op)
{
    u32 perm;

    switch ( op )
    {
    case XEN_DOMCTL_SHADOW_OP_OFF:
        perm = SHADOW__DISABLE;
        break;
    case XEN_DOMCTL_SHADOW_OP_ENABLE:
    case XEN_DOMCTL_SHADOW_OP_ENABLE_TEST:
    case XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION:
    case XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION:
        perm = SHADOW__ENABLE;
        break;
    case XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY:
    case XEN_DOMCTL_SHADOW_OP_PEEK:
    case XEN_DOMCTL_SHADOW_OP_CLEAN:
        perm = SHADOW__LOGDIRTY;
        break;
    default:
        return avc_unknown_permission("shadow_control", op);
    }

    return current_has_perm(d, SECCLASS_SHADOW, perm);
}

struct ioport_has_perm_data {
    u32 ssid;
    u32 dsid;
    u32 perm;
    u32 use_perm;
};

static int _ioport_has_perm(void *v, u32 sid, unsigned long start, unsigned long end)
{
    struct ioport_has_perm_data *data = v;
    struct avc_audit_data ad;
    int rc;

    AVC_AUDIT_DATA_INIT(&ad, RANGE);
    ad.range.start = start;
    ad.range.end = end;

    rc = avc_has_perm(data->ssid, sid, SECCLASS_RESOURCE, data->perm, &ad);

    if ( rc )
        return rc;

    return avc_has_perm(data->dsid, sid, SECCLASS_RESOURCE, data->use_perm, &ad);
}

static int flask_ioport_permission(struct domain *d, uint32_t start, uint32_t end, uint8_t access)
{
    int rc;
    struct ioport_has_perm_data data;

    rc = current_has_perm(d, SECCLASS_RESOURCE,
                         resource_to_perm(access));

    if ( rc )
        return rc;

    if ( access )
        data.perm = RESOURCE__ADD_IOPORT;
    else
        data.perm = RESOURCE__REMOVE_IOPORT;

    data.ssid = domain_sid(current->domain);
    data.dsid = domain_sid(d);
    data.use_perm = flask_iommu_resource_use_perm(d);

    return security_iterate_ioport_sids(start, end, _ioport_has_perm, &data);
}

static int flask_ioport_mapping(struct domain *d, uint32_t start, uint32_t end, uint8_t access)
{
    return flask_ioport_permission(d, start, end, access);
}

static int flask_mem_sharing_op(struct domain *d, struct domain *cd, int op)
{
    int rc = current_has_perm(cd, SECCLASS_HVM, HVM__MEM_SHARING);
    if ( rc )
        return rc;
    return domain_has_perm(d, cd, SECCLASS_HVM, HVM__SHARE_MEM);
}

static int flask_apic(struct domain *d, int cmd)
{
    u32 perm;

    switch ( cmd )
    {
    case PHYSDEVOP_apic_read:
    case PHYSDEVOP_alloc_irq_vector:
        perm = XEN__READAPIC;
        break;
    case PHYSDEVOP_apic_write:
        perm = XEN__WRITEAPIC;
        break;
    default:
        return avc_unknown_permission("apic", cmd);
    }

    return domain_has_xen(d, perm);
}

static int flask_machine_memory_map(void)
{
    return avc_current_has_perm(SECINITSID_XEN, SECCLASS_MMU, MMU__MEMORYMAP, NULL);
}

static int flask_domain_memory_map(struct domain *d)
{
    return current_has_perm(d, SECCLASS_MMU, MMU__MEMORYMAP);
}

static int flask_mmu_update(struct domain *d, struct domain *t,
                            struct domain *f, uint32_t flags)
{
    int rc = 0;
    u32 map_perms = 0;

    if ( t && d != t )
        rc = domain_has_perm(d, t, SECCLASS_MMU, MMU__REMOTE_REMAP);
    if ( rc )
        return rc;

    if ( flags & XSM_MMU_UPDATE_READ )
        map_perms |= MMU__MAP_READ;
    if ( flags & XSM_MMU_UPDATE_WRITE )
        map_perms |= MMU__MAP_WRITE;
    if ( flags & XSM_MMU_MACHPHYS_UPDATE )
        map_perms |= MMU__UPDATEMP;

    if ( map_perms )
        rc = domain_has_perm(d, f, SECCLASS_MMU, map_perms);
    return rc;
}

static int flask_mmuext_op(struct domain *d, struct domain *f)
{
    return domain_has_perm(d, f, SECCLASS_MMU, MMU__MMUEXT_OP);
}

static int flask_update_va_mapping(struct domain *d, struct domain *f,
                                   l1_pgentry_t pte)
{
    u32 map_perms = MMU__MAP_READ;
    if ( !(l1e_get_flags(pte) & _PAGE_PRESENT) )
        return 0;
    if ( l1e_get_flags(pte) & _PAGE_RW )
        map_perms |= MMU__MAP_WRITE;

    return domain_has_perm(d, f, SECCLASS_MMU, map_perms);
}

static int flask_priv_mapping(struct domain *d, struct domain *t)
{
    return domain_has_perm(d, t, SECCLASS_MMU, MMU__TARGET_HACK);
}

static int flask_pmu_op (struct domain *d, unsigned int op)
{
    u32 dsid = domain_sid(d);

    switch ( op )
    {
    case XENPMU_mode_set:
    case XENPMU_mode_get:
    case XENPMU_feature_set:
    case XENPMU_feature_get:
        return avc_has_perm(dsid, SECINITSID_XEN, SECCLASS_XEN2,
                            XEN2__PMU_CTRL, NULL);
    case XENPMU_init:
    case XENPMU_finish:
    case XENPMU_lvtpc_set:
    case XENPMU_flush:
        return avc_has_perm(dsid, SECINITSID_XEN, SECCLASS_XEN2,
                            XEN2__PMU_USE, NULL);
    default:
        return -EPERM;
    }
}

static int flask_dm_op(struct domain *d)
{
    return current_has_perm(d, SECCLASS_HVM, HVM__DM);
}

#endif /* CONFIG_X86 */

static int flask_xen_version (uint32_t op)
{
    u32 dsid = domain_sid(current->domain);

    switch ( op )
    {
    case XENVER_version:
    case XENVER_platform_parameters:
    case XENVER_get_features:
        /* These sub-ops ignore the permission checks and return data. */
        return 0;
    case XENVER_extraversion:
        return avc_has_perm(dsid, SECINITSID_XEN, SECCLASS_VERSION,
                            VERSION__XEN_EXTRAVERSION, NULL);
    case XENVER_compile_info:
        return avc_has_perm(dsid, SECINITSID_XEN, SECCLASS_VERSION,
                            VERSION__XEN_COMPILE_INFO, NULL);
    case XENVER_capabilities:
        return avc_has_perm(dsid, SECINITSID_XEN, SECCLASS_VERSION,
                            VERSION__XEN_CAPABILITIES, NULL);
    case XENVER_changeset:
        return avc_has_perm(dsid, SECINITSID_XEN, SECCLASS_VERSION,
                            VERSION__XEN_CHANGESET, NULL);
    case XENVER_pagesize:
        return avc_has_perm(dsid, SECINITSID_XEN, SECCLASS_VERSION,
                            VERSION__XEN_PAGESIZE, NULL);
    case XENVER_guest_handle:
        return avc_has_perm(dsid, SECINITSID_XEN, SECCLASS_VERSION,
                            VERSION__XEN_GUEST_HANDLE, NULL);
    case XENVER_commandline:
        return avc_has_perm(dsid, SECINITSID_XEN, SECCLASS_VERSION,
                            VERSION__XEN_COMMANDLINE, NULL);
    case XENVER_build_id:
        return avc_has_perm(dsid, SECINITSID_XEN, SECCLASS_VERSION,
                            VERSION__XEN_BUILD_ID, NULL);
    default:
        return -EPERM;
    }
}

static int flask_domain_resource_map(struct domain *d)
{
    return current_has_perm(d, SECCLASS_DOMAIN2, DOMAIN2__RESOURCE_MAP);
}

#ifdef CONFIG_ARGO
static int flask_argo_enable(const struct domain *d)
{
    return avc_has_perm(domain_sid(d), SECINITSID_XEN, SECCLASS_ARGO,
                        ARGO__ENABLE, NULL);
}

static int flask_argo_register_single_source(const struct domain *d,
                                             const struct domain *t)
{
    return domain_has_perm(d, t, SECCLASS_ARGO,
                           ARGO__REGISTER_SINGLE_SOURCE);
}

static int flask_argo_register_any_source(const struct domain *d)
{
    return avc_has_perm(domain_sid(d), SECINITSID_XEN, SECCLASS_ARGO,
                        ARGO__REGISTER_ANY_SOURCE, NULL);
}

static int flask_argo_send(const struct domain *d, const struct domain *t)
{
    return domain_has_perm(d, t, SECCLASS_ARGO, ARGO__SEND);
}

#endif

long do_flask_op(XEN_GUEST_HANDLE_PARAM(xsm_op_t) u_flask_op);
int compat_flask_op(XEN_GUEST_HANDLE_PARAM(xsm_op_t) u_flask_op);

static struct xsm_operations flask_ops = {
    .security_domaininfo = flask_security_domaininfo,
    .domain_create = flask_domain_create,
    .getdomaininfo = flask_getdomaininfo,
    .domctl_scheduler_op = flask_domctl_scheduler_op,
    .sysctl_scheduler_op = flask_sysctl_scheduler_op,
    .set_target = flask_set_target,
    .domctl = flask_domctl,
    .sysctl = flask_sysctl,
    .readconsole = flask_readconsole,

    .evtchn_unbound = flask_evtchn_unbound,
    .evtchn_interdomain = flask_evtchn_interdomain,
    .evtchn_close_post = flask_evtchn_close_post,
    .evtchn_send = flask_evtchn_send,
    .evtchn_status = flask_evtchn_status,
    .evtchn_reset = flask_evtchn_reset,

    .grant_mapref = flask_grant_mapref,
    .grant_unmapref = flask_grant_unmapref,
    .grant_setup = flask_grant_setup,
    .grant_transfer = flask_grant_transfer,
    .grant_copy = flask_grant_copy,
    .grant_query_size = flask_grant_query_size,

    .alloc_security_domain = flask_domain_alloc_security,
    .free_security_domain = flask_domain_free_security,
    .alloc_security_evtchn = flask_alloc_security_evtchn,
    .free_security_evtchn = flask_free_security_evtchn,
    .show_security_evtchn = flask_show_security_evtchn,
    .init_hardware_domain = flask_init_hardware_domain,

    .get_pod_target = flask_get_pod_target,
    .set_pod_target = flask_set_pod_target,
    .memory_exchange = flask_memory_exchange,
    .memory_adjust_reservation = flask_memory_adjust_reservation,
    .memory_stat_reservation = flask_memory_stat_reservation,
    .memory_pin_page = flask_memory_pin_page,
    .claim_pages = flask_claim_pages,

    .console_io = flask_console_io,

    .profile = flask_profile,

    .kexec = flask_kexec,
    .schedop_shutdown = flask_schedop_shutdown,

    .show_irq_sid = flask_show_irq_sid,

    .map_domain_pirq = flask_map_domain_pirq,
    .map_domain_irq = flask_map_domain_irq,
    .unmap_domain_pirq = flask_unmap_domain_pirq,
    .unmap_domain_irq = flask_unmap_domain_irq,
    .bind_pt_irq = flask_bind_pt_irq,
    .unbind_pt_irq = flask_unbind_pt_irq,
    .irq_permission = flask_irq_permission,
    .iomem_permission = flask_iomem_permission,
    .iomem_mapping = flask_iomem_mapping,
    .pci_config_permission = flask_pci_config_permission,

    .resource_plug_core = flask_resource_plug_core,
    .resource_unplug_core = flask_resource_unplug_core,
    .resource_plug_pci = flask_resource_plug_pci,
    .resource_unplug_pci = flask_resource_unplug_pci,
    .resource_setup_pci = flask_resource_setup_pci,
    .resource_setup_gsi = flask_resource_setup_gsi,
    .resource_setup_misc = flask_resource_setup_misc,

    .page_offline = flask_page_offline,
    .hvm_param = flask_hvm_param,
    .hvm_control = flask_hvm_param,
    .hvm_param_nested = flask_hvm_param_nested,
    .hvm_param_altp2mhvm = flask_hvm_param_altp2mhvm,
    .hvm_altp2mhvm_op = flask_hvm_altp2mhvm_op,

    .do_xsm_op = do_flask_op,
    .get_vnumainfo = flask_get_vnumainfo,

    .vm_event_control = flask_vm_event_control,

#ifdef CONFIG_MEM_ACCESS
    .mem_access = flask_mem_access,
#endif

#ifdef CONFIG_HAS_MEM_PAGING
    .mem_paging = flask_mem_paging,
#endif

#ifdef CONFIG_MEM_SHARING
    .mem_sharing = flask_mem_sharing,
#endif

#ifdef CONFIG_COMPAT
    .do_compat_op = compat_flask_op,
#endif

    .add_to_physmap = flask_add_to_physmap,
    .remove_from_physmap = flask_remove_from_physmap,
    .map_gmfn_foreign = flask_map_gmfn_foreign,

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_PCI)
    .get_device_group = flask_get_device_group,
    .assign_device = flask_assign_device,
    .deassign_device = flask_deassign_device,
#endif

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_DEVICE_TREE)
    .assign_dtdevice = flask_assign_dtdevice,
    .deassign_dtdevice = flask_deassign_dtdevice,
#endif

    .platform_op = flask_platform_op,
#ifdef CONFIG_X86
    .do_mca = flask_do_mca,
    .shadow_control = flask_shadow_control,
    .mem_sharing_op = flask_mem_sharing_op,
    .apic = flask_apic,
    .machine_memory_map = flask_machine_memory_map,
    .domain_memory_map = flask_domain_memory_map,
    .mmu_update = flask_mmu_update,
    .mmuext_op = flask_mmuext_op,
    .update_va_mapping = flask_update_va_mapping,
    .priv_mapping = flask_priv_mapping,
    .ioport_permission = flask_ioport_permission,
    .ioport_mapping = flask_ioport_mapping,
    .pmu_op = flask_pmu_op,
    .dm_op = flask_dm_op,
#endif
    .xen_version = flask_xen_version,
    .domain_resource_map = flask_domain_resource_map,
#ifdef CONFIG_ARGO
    .argo_enable = flask_argo_enable,
    .argo_register_single_source = flask_argo_register_single_source,
    .argo_register_any_source = flask_argo_register_any_source,
    .argo_send = flask_argo_send,
#endif
};

void __init flask_init(const void *policy_buffer, size_t policy_size)
{
    int ret = -ENOENT;

    switch ( flask_bootparam )
    {
    case FLASK_BOOTPARAM_DISABLED:
        printk(XENLOG_INFO "Flask: Disabled at boot.\n");
        return;

    case FLASK_BOOTPARAM_PERMISSIVE:
        flask_enforcing = 0;
        break;

    case FLASK_BOOTPARAM_ENFORCING:
    case FLASK_BOOTPARAM_LATELOAD:
        break;

    case FLASK_BOOTPARAM_INVALID:
    default:
        panic("Flask: Invalid value for flask= boot parameter.\n");
    }

    avc_init();

    if ( register_xsm(&flask_ops) )
        panic("Flask: Unable to register with XSM\n");

    if ( policy_size && flask_bootparam != FLASK_BOOTPARAM_LATELOAD )
        ret = security_load_policy(policy_buffer, policy_size);

    if ( ret && flask_bootparam == FLASK_BOOTPARAM_ENFORCING )
        panic("Unable to load FLASK policy\n");

    if ( ret )
        printk(XENLOG_INFO "Flask:  Access controls disabled until policy is loaded.\n");
    else if ( flask_enforcing )
        printk(XENLOG_INFO "Flask:  Starting in enforcing mode.\n");
    else
        printk(XENLOG_INFO "Flask:  Starting in permissive mode.\n");
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
