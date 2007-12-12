/******************************************************************************
 * Arch-specific domctl.c
 * 
 * Copyright (c) 2002-2006, K A Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/guest_access.h>
#include <xen/compat.h>
#include <public/domctl.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <asm/msr.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <asm/paging.h>
#include <asm/irq.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/cacheattr.h>
#include <asm/processor.h>
#include <xsm/xsm.h>
#include <asm/iommu.h>

long arch_do_domctl(
    struct xen_domctl *domctl,
    XEN_GUEST_HANDLE(xen_domctl_t) u_domctl)
{
    long ret = 0;

    switch ( domctl->cmd )
    {

    case XEN_DOMCTL_shadow_op:
    {
        struct domain *d;
        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d != NULL )
        {
            ret = paging_domctl(d,
                                &domctl->u.shadow_op,
                                guest_handle_cast(u_domctl, void));
            rcu_unlock_domain(d);
            copy_to_guest(u_domctl, domctl, 1);
        } 
    }
    break;

    case XEN_DOMCTL_ioport_permission:
    {
        struct domain *d;
        unsigned int fp = domctl->u.ioport_permission.first_port;
        unsigned int np = domctl->u.ioport_permission.nr_ports;

        ret = -EINVAL;
        if ( (fp + np) > 65536 )
            break;

        ret = -ESRCH;
        if ( unlikely((d = rcu_lock_domain_by_id(domctl->domain)) == NULL) )
            break;

        ret = xsm_ioport_permission(d, fp, 
                                    domctl->u.ioport_permission.allow_access);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        if ( np == 0 )
            ret = 0;
        else if ( domctl->u.ioport_permission.allow_access )
            ret = ioports_permit_access(d, fp, fp + np - 1);
        else
            ret = ioports_deny_access(d, fp, fp + np - 1);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_getpageframeinfo:
    {
        struct page_info *page;
        unsigned long mfn = domctl->u.getpageframeinfo.gmfn;
        domid_t dom = domctl->domain;
        struct domain *d;

        ret = -EINVAL;

        if ( unlikely(!mfn_valid(mfn)) ||
             unlikely((d = rcu_lock_domain_by_id(dom)) == NULL) )
            break;

        page = mfn_to_page(mfn);

        ret = xsm_getpageframeinfo(page);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        if ( likely(get_page(page, d)) )
        {
            ret = 0;

            domctl->u.getpageframeinfo.type = XEN_DOMCTL_PFINFO_NOTAB;

            if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
            {
                switch ( page->u.inuse.type_info & PGT_type_mask )
                {
                case PGT_l1_page_table:
                    domctl->u.getpageframeinfo.type = XEN_DOMCTL_PFINFO_L1TAB;
                    break;
                case PGT_l2_page_table:
                    domctl->u.getpageframeinfo.type = XEN_DOMCTL_PFINFO_L2TAB;
                    break;
                case PGT_l3_page_table:
                    domctl->u.getpageframeinfo.type = XEN_DOMCTL_PFINFO_L3TAB;
                    break;
                case PGT_l4_page_table:
                    domctl->u.getpageframeinfo.type = XEN_DOMCTL_PFINFO_L4TAB;
                    break;
                }
            }
            
            put_page(page);
        }

        rcu_unlock_domain(d);

        copy_to_guest(u_domctl, domctl, 1);
    }
    break;

    case XEN_DOMCTL_getpageframeinfo2:
    {
        int n,j;
        int num = domctl->u.getpageframeinfo2.num;
        domid_t dom = domctl->domain;
        struct domain *d;
        uint32_t *arr32;
        ret = -ESRCH;

        if ( unlikely((d = rcu_lock_domain_by_id(dom)) == NULL) )
            break;

        if ( unlikely(num > 1024) )
        {
            ret = -E2BIG;
            rcu_unlock_domain(d);
            break;
        }

        arr32 = alloc_xenheap_page();
        if ( !arr32 )
        {
            ret = -ENOMEM;
            put_domain(d);
            break;
        }
 
        ret = 0;
        for ( n = 0; n < num; )
        {
            int k = PAGE_SIZE / 4;
            if ( (num - n) < k )
                k = num - n;

            if ( copy_from_guest_offset(arr32,
                                        domctl->u.getpageframeinfo2.array,
                                        n, k) )
            {
                ret = -EFAULT;
                break;
            }
     
            for ( j = 0; j < k; j++ )
            {      
                struct page_info *page;
                unsigned long mfn = arr32[j];

                page = mfn_to_page(mfn);

                ret = xsm_getpageframeinfo(page);
                if ( ret )
                    continue;

                if ( likely(mfn_valid(mfn) && get_page(page, d)) ) 
                {
                    unsigned long type = 0;

                    switch( page->u.inuse.type_info & PGT_type_mask )
                    {
                    case PGT_l1_page_table:
                        type = XEN_DOMCTL_PFINFO_L1TAB;
                        break;
                    case PGT_l2_page_table:
                        type = XEN_DOMCTL_PFINFO_L2TAB;
                        break;
                    case PGT_l3_page_table:
                        type = XEN_DOMCTL_PFINFO_L3TAB;
                        break;
                    case PGT_l4_page_table:
                        type = XEN_DOMCTL_PFINFO_L4TAB;
                        break;
                    }

                    if ( page->u.inuse.type_info & PGT_pinned )
                        type |= XEN_DOMCTL_PFINFO_LPINTAB;
                    arr32[j] |= type;
                    put_page(page);
                }
                else
                    arr32[j] |= XEN_DOMCTL_PFINFO_XTAB;

            }

            if ( copy_to_guest_offset(domctl->u.getpageframeinfo2.array,
                                      n, arr32, k) )
            {
                ret = -EFAULT;
                break;
            }

            n += k;
        }

        free_xenheap_page(arr32);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_getmemlist:
    {
        int i;
        struct domain *d = rcu_lock_domain_by_id(domctl->domain);
        unsigned long max_pfns = domctl->u.getmemlist.max_pfns;
        uint64_t mfn;
        struct list_head *list_ent;

        ret = -EINVAL;
        if ( d != NULL )
        {
            ret = xsm_getmemlist(d);
            if ( ret )
            {
                rcu_unlock_domain(d);
                break;
            }

            spin_lock(&d->page_alloc_lock);

            if ( unlikely(d->is_dying) ) {
                spin_unlock(&d->page_alloc_lock);
                goto getmemlist_out;
            }

            ret = 0;
            list_ent = d->page_list.next;
            for ( i = 0; (i < max_pfns) && (list_ent != &d->page_list); i++ )
            {
                mfn = page_to_mfn(list_entry(
                    list_ent, struct page_info, list));
                if ( copy_to_guest_offset(domctl->u.getmemlist.buffer,
                                          i, &mfn, 1) )
                {
                    ret = -EFAULT;
                    break;
                }
                list_ent = mfn_to_page(mfn)->list.next;
            }
            
            spin_unlock(&d->page_alloc_lock);

            domctl->u.getmemlist.num_pfns = i;
            copy_to_guest(u_domctl, domctl, 1);
        getmemlist_out:
            rcu_unlock_domain(d);
        }
    }
    break;

    case XEN_DOMCTL_hypercall_init:
    {
        struct domain *d = rcu_lock_domain_by_id(domctl->domain);
        unsigned long gmfn = domctl->u.hypercall_init.gmfn;
        unsigned long mfn;
        void *hypercall_page;

        ret = -ESRCH;
        if ( unlikely(d == NULL) )
            break;

        ret = xsm_hypercall_init(d);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        mfn = gmfn_to_mfn(d, gmfn);

        ret = -EACCES;
        if ( !mfn_valid(mfn) ||
             !get_page_and_type(mfn_to_page(mfn), d, PGT_writable_page) )
        {
            rcu_unlock_domain(d);
            break;
        }

        ret = 0;

        hypercall_page = map_domain_page(mfn);
        hypercall_page_initialise(d, hypercall_page);
        unmap_domain_page(hypercall_page);

        put_page_and_type(mfn_to_page(mfn));

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_sethvmcontext:
    { 
        struct hvm_domain_context c;
        struct domain             *d;

        c.cur = 0;
        c.size = domctl->u.hvmcontext.size;
        c.data = NULL;
        
        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_hvmcontext(d, domctl->cmd);
        if ( ret )
            goto sethvmcontext_out;

        ret = -EINVAL;
        if ( !is_hvm_domain(d) ) 
            goto sethvmcontext_out;

        ret = -ENOMEM;
        if ( (c.data = xmalloc_bytes(c.size)) == NULL )
            goto sethvmcontext_out;

        ret = -EFAULT;
        if ( copy_from_guest(c.data, domctl->u.hvmcontext.buffer, c.size) != 0)
            goto sethvmcontext_out;

        domain_pause(d);
        ret = hvm_load(d, &c);
        domain_unpause(d);

    sethvmcontext_out:
        if ( c.data != NULL )
            xfree(c.data);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_gethvmcontext:
    { 
        struct hvm_domain_context c;
        struct domain             *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_hvmcontext(d, domctl->cmd);
        if ( ret )
            goto gethvmcontext_out;

        ret = -EINVAL;
        if ( !is_hvm_domain(d) ) 
            goto gethvmcontext_out;

        c.cur = 0;
        c.size = hvm_save_size(d);
        c.data = NULL;

        if ( guest_handle_is_null(domctl->u.hvmcontext.buffer) )
        {
            /* Client is querying for the correct buffer size */
            domctl->u.hvmcontext.size = c.size;
            ret = 0;
            goto gethvmcontext_out;            
        }

        /* Check that the client has a big enough buffer */
        ret = -ENOSPC;
        if ( domctl->u.hvmcontext.size < c.size ) 
            goto gethvmcontext_out;

        /* Allocate our own marshalling buffer */
        ret = -ENOMEM;
        if ( (c.data = xmalloc_bytes(c.size)) == NULL )
            goto gethvmcontext_out;

        domain_pause(d);
        ret = hvm_save(d, &c);
        domain_unpause(d);

        domctl->u.hvmcontext.size = c.cur;
        if ( copy_to_guest(domctl->u.hvmcontext.buffer, c.data, c.size) != 0 )
            ret = -EFAULT;

    gethvmcontext_out:
        if ( copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;

        if ( c.data != NULL )
            xfree(c.data);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_set_address_size:
    {
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_address_size(d, domctl->cmd);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        switch ( domctl->u.address_size.size )
        {
#ifdef CONFIG_COMPAT
        case 32:
            ret = switch_compat(d);
            break;
        case 64:
            ret = switch_native(d);
            break;
#endif
        default:
            ret = (domctl->u.address_size.size == BITS_PER_LONG) ? 0 : -EINVAL;
            break;
        }

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_get_address_size:
    {
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_address_size(d, domctl->cmd);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        domctl->u.address_size.size = BITS_PER_GUEST_LONG(d);

        ret = 0;
        rcu_unlock_domain(d);

        if ( copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;
    }
    break;

    case XEN_DOMCTL_sendtrigger:
    {
        struct domain *d;
        struct vcpu *v;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = -EINVAL;
        if ( domctl->u.sendtrigger.vcpu >= MAX_VIRT_CPUS )
            goto sendtrigger_out;

        ret = -ESRCH;
        if ( (v = d->vcpu[domctl->u.sendtrigger.vcpu]) == NULL )
            goto sendtrigger_out;

        switch ( domctl->u.sendtrigger.trigger )
        {
        case XEN_DOMCTL_SENDTRIGGER_NMI:
        {
            ret = 0;
            if ( !test_and_set_bool(v->nmi_pending) )
                vcpu_kick(v);
        }
        break;

        default:
            ret = -ENOSYS;
        }

    sendtrigger_out:
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_test_assign_device:
    {
        u8 bus, devfn;

        ret = -EINVAL;
        if ( !vtd_enabled )
            break;

        bus = (domctl->u.assign_device.machine_bdf >> 16) & 0xff;
        devfn = (domctl->u.assign_device.machine_bdf >> 8) & 0xff;

        if ( device_assigned(bus, devfn) )
        {
            gdprintk(XENLOG_ERR, "XEN_DOMCTL_test_assign_device: "
                     "%x:%x:%x already assigned\n",
                     bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
            break;
        }
        ret = 0;
    }
    break;

    case XEN_DOMCTL_assign_device:
    {
        struct domain *d;
        u8 bus, devfn;

        ret = -EINVAL;
        if ( !vtd_enabled )
            break;

        if ( unlikely((d = get_domain_by_id(domctl->domain)) == NULL) )
        {
            gdprintk(XENLOG_ERR,
                "XEN_DOMCTL_assign_device: get_domain_by_id() failed\n");
            break;
        }
        bus = (domctl->u.assign_device.machine_bdf >> 16) & 0xff;
        devfn = (domctl->u.assign_device.machine_bdf >> 8) & 0xff;

        if ( device_assigned(bus, devfn) )
        {
            gdprintk(XENLOG_ERR, "XEN_DOMCTL_assign_device: "
                     "%x:%x:%x already assigned\n",
                     bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
            break;
        }

        ret = assign_device(d, bus, devfn);
        gdprintk(XENLOG_INFO, "XEN_DOMCTL_assign_device: bdf = %x:%x:%x\n",
            bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
        put_domain(d);
    }
    break;

    case XEN_DOMCTL_bind_pt_irq:
    {
        struct domain * d;
        xen_domctl_bind_pt_irq_t * bind;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;
        bind = &(domctl->u.bind_pt_irq);
        if (vtd_enabled)
            ret = pt_irq_create_bind_vtd(d, bind);
        if (ret < 0)
            gdprintk(XENLOG_ERR, "pt_irq_create_bind failed!\n");
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_memory_mapping:
    {
        struct domain *d;
        unsigned long gfn = domctl->u.memory_mapping.first_gfn;
        unsigned long mfn = domctl->u.memory_mapping.first_mfn;
        unsigned long nr_mfns = domctl->u.memory_mapping.nr_mfns;
        int i;

        ret = -EINVAL;
        if ( (mfn + nr_mfns - 1) < mfn ) /* wrap? */
            break;

        ret = -ESRCH;
        if ( unlikely((d = rcu_lock_domain_by_id(domctl->domain)) == NULL) )
            break;

        ret=0;
        if ( domctl->u.memory_mapping.add_mapping )
        {
            gdprintk(XENLOG_INFO,
                "memory_map:add: gfn=%lx mfn=%lx nr_mfns=%lx\n",
                gfn, mfn, nr_mfns);

            ret = iomem_permit_access(d, mfn, mfn + nr_mfns - 1);
            for ( i = 0; i < nr_mfns; i++ )
                set_mmio_p2m_entry(d, gfn+i, _mfn(mfn+i));
        }
        else
        {
            gdprintk(XENLOG_INFO,
                "memory_map:remove: gfn=%lx mfn=%lx nr_mfns=%lx\n",
                 gfn, mfn, nr_mfns);

            for ( i = 0; i < nr_mfns; i++ )
                clear_mmio_p2m_entry(d, gfn+i);
            ret = iomem_deny_access(d, mfn, mfn + nr_mfns - 1);
        }

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_ioport_mapping:
    {
#define MAX_IOPORTS    0x10000
        struct domain *d;
        struct hvm_iommu *hd;
        unsigned int fgp = domctl->u.ioport_mapping.first_gport;
        unsigned int fmp = domctl->u.ioport_mapping.first_mport;
        unsigned int np = domctl->u.ioport_mapping.nr_ports;
        struct g2m_ioport *g2m_ioport;
        int found = 0;

        ret = -EINVAL;
        if ( (np == 0) || (fgp > MAX_IOPORTS) || (fmp > MAX_IOPORTS) ||
            ((fgp + np) > MAX_IOPORTS) || ((fmp + np) > MAX_IOPORTS) )
        {
            gdprintk(XENLOG_ERR,
                "ioport_map:invalid:gport=%x mport=%x nr_ports=%x\n",
                fgp, fmp, np);
            break;
        }

        ret = -ESRCH;
        if ( unlikely((d = rcu_lock_domain_by_id(domctl->domain)) == NULL) )
            break;

        hd = domain_hvm_iommu(d);
        if ( domctl->u.ioport_mapping.add_mapping )
        {
            gdprintk(XENLOG_INFO,
                "ioport_map:add f_gport=%x f_mport=%x np=%x\n",
                fgp, fmp, np);

            list_for_each_entry(g2m_ioport, &hd->g2m_ioport_list, list)
                if (g2m_ioport->mport == fmp )
                {
                    g2m_ioport->gport = fgp;
                    g2m_ioport->np = np;
                    found = 1;
                    break;
                }
            if ( !found )
            {
                g2m_ioport = xmalloc(struct g2m_ioport);
                g2m_ioport->gport = fgp;
                g2m_ioport->mport = fmp;
                g2m_ioport->np = np;
                list_add_tail(&g2m_ioport->list, &hd->g2m_ioport_list);
            }
            ret = ioports_permit_access(d, fmp, fmp + np - 1);
        }
        else
        {
            gdprintk(XENLOG_INFO,
                "ioport_map:remove f_gport=%x f_mport=%x np=%x\n",
                fgp, fmp, np);
            list_for_each_entry(g2m_ioport, &hd->g2m_ioport_list, list)
                if ( g2m_ioport->mport == fmp )
                {
                    list_del(&g2m_ioport->list);
                    xfree(g2m_ioport);
                    break;
                }
            ret = ioports_deny_access(d, fmp, fmp + np - 1);
        }
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_pin_mem_cacheattr:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d == NULL )
            break;

        ret = hvm_set_mem_pinned_cacheattr(
            d, domctl->u.pin_mem_cacheattr.start,
            domctl->u.pin_mem_cacheattr.end,
            domctl->u.pin_mem_cacheattr.type);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_set_ext_vcpucontext:
    case XEN_DOMCTL_get_ext_vcpucontext:
    {
        struct xen_domctl_ext_vcpucontext *evc;
        struct domain *d;
        struct vcpu *v;

        evc = &domctl->u.ext_vcpucontext;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d == NULL )
            break;

        ret = -ESRCH;
        if ( (evc->vcpu >= MAX_VIRT_CPUS) ||
             ((v = d->vcpu[evc->vcpu]) == NULL) )
            goto ext_vcpucontext_out;

        if ( domctl->cmd == XEN_DOMCTL_get_ext_vcpucontext )
        {
            evc->size = sizeof(*evc);
#ifdef __x86_64__
            evc->sysenter_callback_cs      = v->arch.sysenter_callback_cs;
            evc->sysenter_callback_eip     = v->arch.sysenter_callback_eip;
            evc->sysenter_disables_events  = v->arch.sysenter_disables_events;
            evc->syscall32_callback_cs     = v->arch.syscall32_callback_cs;
            evc->syscall32_callback_eip    = v->arch.syscall32_callback_eip;
            evc->syscall32_disables_events = v->arch.syscall32_disables_events;
#else
            evc->sysenter_callback_cs      = 0;
            evc->sysenter_callback_eip     = 0;
            evc->sysenter_disables_events  = 0;
            evc->syscall32_callback_cs     = 0;
            evc->syscall32_callback_eip    = 0;
            evc->syscall32_disables_events = 0;
#endif
        }
        else
        {
            ret = -EINVAL;
            if ( evc->size != sizeof(*evc) )
                goto ext_vcpucontext_out;
#ifdef __x86_64__
            fixup_guest_code_selector(d, evc->sysenter_callback_cs);
            v->arch.sysenter_callback_cs      = evc->sysenter_callback_cs;
            v->arch.sysenter_callback_eip     = evc->sysenter_callback_eip;
            v->arch.sysenter_disables_events  = evc->sysenter_disables_events;
            fixup_guest_code_selector(d, evc->syscall32_callback_cs);
            v->arch.syscall32_callback_cs     = evc->syscall32_callback_cs;
            v->arch.syscall32_callback_eip    = evc->syscall32_callback_eip;
            v->arch.syscall32_disables_events = evc->syscall32_disables_events;
#else
            /* We do not support syscall/syscall32/sysenter on 32-bit Xen. */
            if ( (evc->sysenter_callback_cs & ~3) ||
                 evc->sysenter_callback_eip ||
                 (evc->syscall32_callback_cs & ~3) ||
                 evc->syscall32_callback_eip )
                goto ext_vcpucontext_out;
#endif
        }

        ret = 0;

    ext_vcpucontext_out:
        rcu_unlock_domain(d);
        if ( (domctl->cmd == XEN_DOMCTL_get_ext_vcpucontext) &&
             copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

void arch_get_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
#ifdef CONFIG_COMPAT
#define c(fld) (!is_pv_32on64_domain(v->domain) ? (c.nat->fld) : (c.cmp->fld))
#else
#define c(fld) (c.nat->fld)
#endif

    if ( !is_pv_32on64_domain(v->domain) )
        memcpy(c.nat, &v->arch.guest_context, sizeof(*c.nat));
#ifdef CONFIG_COMPAT
    else
        XLAT_vcpu_guest_context(c.cmp, &v->arch.guest_context);
#endif

    c(flags &= ~(VGCF_i387_valid|VGCF_in_kernel));
    if ( v->fpu_initialised )
        c(flags |= VGCF_i387_valid);
    if ( !test_bit(_VPF_down, &v->pause_flags) )
        c(flags |= VGCF_online);

    if ( is_hvm_vcpu(v) )
    {
        memset(c.nat->ctrlreg, 0, sizeof(c.nat->ctrlreg));
        c.nat->ctrlreg[0] = v->arch.hvm_vcpu.guest_cr[0];
        c.nat->ctrlreg[2] = v->arch.hvm_vcpu.guest_cr[2];
        c.nat->ctrlreg[3] = v->arch.hvm_vcpu.guest_cr[3];
        c.nat->ctrlreg[4] = v->arch.hvm_vcpu.guest_cr[4];
    }
    else
    {
        /* IOPL privileges are virtualised: merge back into returned eflags. */
        BUG_ON((c(user_regs.eflags) & EF_IOPL) != 0);
        c(user_regs.eflags |= v->arch.iopl << 12);

        if ( !is_pv_32on64_domain(v->domain) )
        {
            c.nat->ctrlreg[3] = xen_pfn_to_cr3(
                pagetable_get_pfn(v->arch.guest_table));
#ifdef __x86_64__
            if ( !pagetable_is_null(v->arch.guest_table_user) )
                c.nat->ctrlreg[1] = xen_pfn_to_cr3(
                    pagetable_get_pfn(v->arch.guest_table_user));
#endif

            /* Merge shadow DR7 bits into real DR7. */
            c.nat->debugreg[7] |= c.nat->debugreg[5];
            c.nat->debugreg[5] = 0;
        }
#ifdef CONFIG_COMPAT
        else
        {
            l4_pgentry_t *l4e = __va(pagetable_get_paddr(v->arch.guest_table));
            c.cmp->ctrlreg[3] = compat_pfn_to_cr3(l4e_get_pfn(*l4e));

            /* Merge shadow DR7 bits into real DR7. */
            c.cmp->debugreg[7] |= c.cmp->debugreg[5];
            c.cmp->debugreg[5] = 0;
        }
#endif

        if ( guest_kernel_mode(v, &v->arch.guest_context.user_regs) )
            c(flags |= VGCF_in_kernel);
    }

    c(vm_assist = v->domain->vm_assist);
#undef c
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
