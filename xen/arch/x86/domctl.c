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
#include <xen/pci.h>
#include <public/domctl.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <asm/msr.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <xen/paging.h>
#include <asm/irq.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/cacheattr.h>
#include <asm/processor.h>
#include <asm/acpi.h> /* for hvm_acpi_power_button */
#include <xen/hypercall.h> /* for arch_do_domctl */
#include <xsm/xsm.h>
#include <xen/iommu.h>
#include <asm/mem_event.h>
#include <public/mem_event.h>
#include <asm/mem_sharing.h>
#include <asm/xstate.h>
#include <asm/debugger.h>

static int gdbsx_guest_mem_io(
    domid_t domid, struct xen_domctl_gdbsx_memio *iop)
{   
    ulong l_uva = (ulong)iop->uva;
    iop->remain = dbg_rw_mem(
        (dbgva_t)iop->gva, (dbgbyte_t *)l_uva, iop->len, domid,
        iop->gwr, iop->pgd3val);
    return (iop->remain ? -EFAULT : 0);
}

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
        int allow = domctl->u.ioport_permission.allow_access;

        ret = -EINVAL;
        if ( (fp + np) > 65536 )
            break;

        ret = -ESRCH;
        if ( unlikely((d = rcu_lock_domain_by_id(domctl->domain)) == NULL) )
            break;

        if ( np == 0 )
            ret = 0;
        else if ( xsm_ioport_permission(d, fp, fp + np - 1, allow) )
            ret = -EPERM;
        else if ( allow )
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

    case XEN_DOMCTL_getpageframeinfo3:
#ifdef __x86_64__
        if (!has_32bit_shinfo(current->domain))
        {
            unsigned int n, j;
            unsigned int num = domctl->u.getpageframeinfo3.num;
            domid_t dom = domctl->domain;
            struct domain *d;
            struct page_info *page;
            xen_pfn_t *arr;

            ret = -ESRCH;
            if ( unlikely((d = rcu_lock_domain_by_id(dom)) == NULL) )
                break;

            if ( unlikely(num > 1024) ||
                 unlikely(num != domctl->u.getpageframeinfo3.num) )
            {
                ret = -E2BIG;
                rcu_unlock_domain(d);
                break;
            }

            page = alloc_domheap_page(NULL, 0);
            if ( !page )
            {
                ret = -ENOMEM;
                rcu_unlock_domain(d);
                break;
            }
            arr = page_to_virt(page);

            for ( n = ret = 0; n < num; )
            {
                unsigned int k = min_t(unsigned int, num - n,
                                       PAGE_SIZE / sizeof(*arr));

                if ( copy_from_guest_offset(arr,
                                            domctl->u.getpageframeinfo3.array,
                                            n, k) )
                {
                    ret = -EFAULT;
                    break;
                }

                for ( j = 0; j < k; j++ )
                {
                    unsigned long type = 0, mfn = get_gfn_untyped(d, arr[j]);

                    page = mfn_to_page(mfn);

                    if ( unlikely(!mfn_valid(mfn)) ||
                         unlikely(is_xen_heap_mfn(mfn)) )
                        type = XEN_DOMCTL_PFINFO_XTAB;
                    else if ( xsm_getpageframeinfo(page) != 0 )
                        ;
                    else if ( likely(get_page(page, d)) )
                    {
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

                        put_page(page);
                    }
                    else
                        type = XEN_DOMCTL_PFINFO_XTAB;

                    put_gfn(d, arr[j]);
                    arr[j] = type;
                }

                if ( copy_to_guest_offset(domctl->u.getpageframeinfo3.array,
                                          n, arr, k) )
                {
                    ret = -EFAULT;
                    break;
                }

                n += k;
            }

            free_domheap_page(virt_to_page(arr));

            rcu_unlock_domain(d);
            break;
        }
#endif
        /* fall thru */
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
            rcu_unlock_domain(d);
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
                unsigned long gfn = arr32[j];
                unsigned long mfn = get_gfn_untyped(d, gfn);

                page = mfn_to_page(mfn);

                if ( domctl->cmd == XEN_DOMCTL_getpageframeinfo3)
                    arr32[j] = 0;

                if ( unlikely(!mfn_valid(mfn)) ||
                     unlikely(is_xen_heap_mfn(mfn)) )
                    arr32[j] |= XEN_DOMCTL_PFINFO_XTAB;
                else if ( xsm_getpageframeinfo(page) != 0 )
                {
                    put_gfn(d, gfn); 
                    continue;
                } else if ( likely(get_page(page, d)) )
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

                put_gfn(d, gfn); 
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
        struct page_info *page;

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

            ret = i = 0;
            page_list_for_each(page, &d->page_list)
            {
                if ( i >= max_pfns )
                    break;
                mfn = page_to_mfn(page);
                if ( copy_to_guest_offset(domctl->u.getmemlist.buffer,
                                          i, &mfn, 1) )
                {
                    ret = -EFAULT;
                    break;
                }
                ++i;
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

        mfn = get_gfn_untyped(d, gmfn);

        ret = -EACCES;
        if ( !mfn_valid(mfn) ||
             !get_page_and_type(mfn_to_page(mfn), d, PGT_writable_page) )
        {
            put_gfn(d, gmfn); 
            rcu_unlock_domain(d);
            break;
        }

        ret = 0;

        hypercall_page = map_domain_page(mfn);
        hypercall_page_initialise(d, hypercall_page);
        unmap_domain_page(hypercall_page);

        put_page_and_type(mfn_to_page(mfn));

        put_gfn(d, gmfn); 
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_sethvmcontext:
    { 
        struct hvm_domain_context c = { .size = domctl->u.hvmcontext.size };
        struct domain *d;

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
        struct hvm_domain_context c = { 0 };
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_hvmcontext(d, domctl->cmd);
        if ( ret )
            goto gethvmcontext_out;

        ret = -EINVAL;
        if ( !is_hvm_domain(d) ) 
            goto gethvmcontext_out;

        c.size = hvm_save_size(d);

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

    case XEN_DOMCTL_gethvmcontext_partial:
    { 
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_hvmcontext(d, domctl->cmd);
        if ( ret )
            goto gethvmcontext_partial_out;

        ret = -EINVAL;
        if ( !is_hvm_domain(d) ) 
            goto gethvmcontext_partial_out;

        domain_pause(d);
        ret = hvm_save_one(d, domctl->u.hvmcontext_partial.type,
                           domctl->u.hvmcontext_partial.instance,
                           domctl->u.hvmcontext_partial.buffer);
        domain_unpause(d);

    gethvmcontext_partial_out:
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

        domctl->u.address_size.size =
            is_pv_32on64_domain(d) ? 32 : BITS_PER_LONG;

        ret = 0;
        rcu_unlock_domain(d);

        if ( copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;
    }
    break;

    case XEN_DOMCTL_set_machine_address_size:
    {
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_machine_address_size(d, domctl->cmd);
        if ( ret )
            goto set_machine_address_size_out;

        ret = -EBUSY;
        if ( d->tot_pages > 0 )
            goto set_machine_address_size_out;

        d->arch.physaddr_bitsize = domctl->u.address_size.size;

        ret = 0;
    set_machine_address_size_out:
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_get_machine_address_size:
    {
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = xsm_machine_address_size(d, domctl->cmd);
        if ( ret )
        {
            rcu_unlock_domain(d);
            break;
        }

        domctl->u.address_size.size = d->arch.physaddr_bitsize;

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

        ret = xsm_sendtrigger(d);
        if ( ret )
            goto sendtrigger_out;

        ret = -EINVAL;
        if ( domctl->u.sendtrigger.vcpu >= MAX_VIRT_CPUS )
            goto sendtrigger_out;

        ret = -ESRCH;
        if ( domctl->u.sendtrigger.vcpu >= d->max_vcpus ||
             (v = d->vcpu[domctl->u.sendtrigger.vcpu]) == NULL )
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

        case XEN_DOMCTL_SENDTRIGGER_POWER:
        {
            ret = -EINVAL;
            if ( is_hvm_domain(d) ) 
            {
                ret = 0;
                hvm_acpi_power_button(d);
            }
        }
        break;

        case XEN_DOMCTL_SENDTRIGGER_SLEEP:
        {
            ret = -EINVAL;
            if ( is_hvm_domain(d) ) 
            {
                ret = 0;
                hvm_acpi_sleep_button(d);
            }
        }
        break;

        default:
            ret = -ENOSYS;
        }

    sendtrigger_out:
        rcu_unlock_domain(d);
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

        ret = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto bind_out;

        ret = xsm_bind_pt_irq(d, bind);
        if ( ret )
            goto bind_out;

        ret = -EPERM;
        if ( !IS_PRIV(current->domain) &&
             !irq_access_permitted(current->domain, bind->machine_irq) )
            goto bind_out;

        ret = -ESRCH;
        if ( iommu_enabled )
        {
            spin_lock(&pcidevs_lock);
            ret = pt_irq_create_bind_vtd(d, bind);
            spin_unlock(&pcidevs_lock);
        }
        if ( ret < 0 )
            printk(XENLOG_G_ERR "pt_irq_create_bind failed (%ld) for dom%d\n",
                   ret, d->domain_id);

    bind_out:
        rcu_unlock_domain(d);
    }
    break;    

    case XEN_DOMCTL_unbind_pt_irq:
    {
        struct domain * d;
        xen_domctl_bind_pt_irq_t * bind;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;
        bind = &(domctl->u.bind_pt_irq);

        ret = -EPERM;
        if ( !IS_PRIV(current->domain) &&
             !irq_access_permitted(current->domain, bind->machine_irq) )
            goto unbind_out;

        if ( iommu_enabled )
        {
            spin_lock(&pcidevs_lock);
            ret = pt_irq_destroy_bind_vtd(d, bind);
            spin_unlock(&pcidevs_lock);
        }
        if ( ret < 0 )
            printk(XENLOG_G_ERR "pt_irq_destroy_bind failed (%ld) for dom%d\n",
                   ret, d->domain_id);

    unbind_out:
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_memory_mapping:
    {
        struct domain *d;
        unsigned long gfn = domctl->u.memory_mapping.first_gfn;
        unsigned long mfn = domctl->u.memory_mapping.first_mfn;
        unsigned long nr_mfns = domctl->u.memory_mapping.nr_mfns;
        int add = domctl->u.memory_mapping.add_mapping;
        int i;

        ret = -EINVAL;
        if ( (mfn + nr_mfns - 1) < mfn ) /* wrap? */
            break;

        ret = -EPERM;
        if ( !IS_PRIV(current->domain) &&
             !iomem_access_permitted(current->domain, mfn, mfn + nr_mfns - 1) )
            break;

        ret = -ESRCH;
        if ( unlikely((d = rcu_lock_domain_by_id(domctl->domain)) == NULL) )
            break;

        ret = xsm_iomem_permission(d, mfn, mfn + nr_mfns - 1, add);
        if ( ret ) {
            rcu_unlock_domain(d);
            break;
        }

        if ( add )
        {
            printk(XENLOG_G_INFO
                   "memory_map:add: dom%d gfn=%lx mfn=%lx nr=%lx\n",
                   d->domain_id, gfn, mfn, nr_mfns);

            ret = iomem_permit_access(d, mfn, mfn + nr_mfns - 1);
            for ( i = 0; i < nr_mfns; i++ )
                set_mmio_p2m_entry(d, gfn+i, _mfn(mfn+i));
        }
        else
        {
            printk(XENLOG_G_INFO
                   "memory_map:remove: dom%d gfn=%lx mfn=%lx nr=%lx\n",
                   d->domain_id, gfn, mfn, nr_mfns);

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
        unsigned int add = domctl->u.ioport_mapping.add_mapping;
        struct g2m_ioport *g2m_ioport;
        int found = 0;

        ret = -EINVAL;
        if ( (np == 0) || (fgp > MAX_IOPORTS) || (fmp > MAX_IOPORTS) ||
            ((fgp + np) > MAX_IOPORTS) || ((fmp + np) > MAX_IOPORTS) )
        {
            printk(XENLOG_G_ERR
                   "ioport_map:invalid:dom%d gport=%x mport=%x nr=%x\n",
                   domctl->domain, fgp, fmp, np);
            break;
        }

        ret = -EPERM;
        if ( !IS_PRIV(current->domain) &&
             !ioports_access_permitted(current->domain, fmp, fmp + np - 1) )
            break;

        ret = -ESRCH;
        if ( unlikely((d = rcu_lock_domain_by_id(domctl->domain)) == NULL) )
            break;

        ret = xsm_ioport_permission(d, fmp, fmp + np - 1, add);
        if ( ret ) {
            rcu_unlock_domain(d);
            break;
        }

        hd = domain_hvm_iommu(d);
        if ( add )
        {
            printk(XENLOG_G_INFO
                   "ioport_map:add: dom%d gport=%x mport=%x nr=%x\n",
                   d->domain_id, fgp, fmp, np);

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
            printk(XENLOG_G_INFO
                   "ioport_map:remove: dom%d gport=%x mport=%x nr=%x\n",
                   d->domain_id, fgp, fmp, np);
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

        ret = xsm_pin_mem_cacheattr(d);
        if ( ret )
            goto pin_out;

        ret = hvm_set_mem_pinned_cacheattr(
            d, domctl->u.pin_mem_cacheattr.start,
            domctl->u.pin_mem_cacheattr.end,
            domctl->u.pin_mem_cacheattr.type);

    pin_out:
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

        ret = xsm_ext_vcpucontext(d, domctl->cmd);
        if ( ret )
            goto ext_vcpucontext_out;

        ret = -ESRCH;
        if ( (evc->vcpu >= d->max_vcpus) ||
             ((v = d->vcpu[evc->vcpu]) == NULL) )
            goto ext_vcpucontext_out;

        if ( domctl->cmd == XEN_DOMCTL_get_ext_vcpucontext )
        {
            evc->size = sizeof(*evc);
#ifdef __x86_64__
            if ( !is_hvm_domain(d) )
            {
                evc->sysenter_callback_cs      =
                    v->arch.pv_vcpu.sysenter_callback_cs;
                evc->sysenter_callback_eip     =
                    v->arch.pv_vcpu.sysenter_callback_eip;
                evc->sysenter_disables_events  =
                    v->arch.pv_vcpu.sysenter_disables_events;
                evc->syscall32_callback_cs     =
                    v->arch.pv_vcpu.syscall32_callback_cs;
                evc->syscall32_callback_eip    =
                    v->arch.pv_vcpu.syscall32_callback_eip;
                evc->syscall32_disables_events =
                    v->arch.pv_vcpu.syscall32_disables_events;
            }
            else
#endif
            {
                evc->sysenter_callback_cs      = 0;
                evc->sysenter_callback_eip     = 0;
                evc->sysenter_disables_events  = 0;
                evc->syscall32_callback_cs     = 0;
                evc->syscall32_callback_eip    = 0;
                evc->syscall32_disables_events = 0;
            }
            evc->mcg_cap = v->arch.mcg_cap;
        }
        else
        {
            ret = -EINVAL;
            if ( evc->size < offsetof(typeof(*evc), mcg_cap) )
                goto ext_vcpucontext_out;
#ifdef __x86_64__
            if ( !is_hvm_domain(d) )
            {
                fixup_guest_code_selector(d, evc->sysenter_callback_cs);
                v->arch.pv_vcpu.sysenter_callback_cs      =
                    evc->sysenter_callback_cs;
                v->arch.pv_vcpu.sysenter_callback_eip     =
                    evc->sysenter_callback_eip;
                v->arch.pv_vcpu.sysenter_disables_events  =
                    evc->sysenter_disables_events;
                fixup_guest_code_selector(d, evc->syscall32_callback_cs);
                v->arch.pv_vcpu.syscall32_callback_cs     =
                    evc->syscall32_callback_cs;
                v->arch.pv_vcpu.syscall32_callback_eip    =
                    evc->syscall32_callback_eip;
                v->arch.pv_vcpu.syscall32_disables_events =
                    evc->syscall32_disables_events;
            }
            else
#endif
            /* We do not support syscall/syscall32/sysenter on 32-bit Xen. */
            if ( (evc->sysenter_callback_cs & ~3) ||
                 evc->sysenter_callback_eip ||
                 (evc->syscall32_callback_cs & ~3) ||
                 evc->syscall32_callback_eip )
                goto ext_vcpucontext_out;

            if ( evc->size >= offsetof(typeof(*evc), mcg_cap) +
                              sizeof(evc->mcg_cap) )
                ret = vmce_restore_vcpu(v, evc->mcg_cap);
        }

        ret = 0;

    ext_vcpucontext_out:
        rcu_unlock_domain(d);
        if ( (domctl->cmd == XEN_DOMCTL_get_ext_vcpucontext) &&
             copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;
    }
    break;

    case XEN_DOMCTL_set_cpuid:
    {
        struct domain *d;
        xen_domctl_cpuid_t *ctl = &domctl->u.cpuid;
        cpuid_input_t *cpuid = NULL; 
        int i;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d == NULL )
            break;

        for ( i = 0; i < MAX_CPUID_INPUT; i++ )
        {
            cpuid = &d->arch.cpuids[i];

            if ( cpuid->input[0] == XEN_CPUID_INPUT_UNUSED )
                break;

            if ( (cpuid->input[0] == ctl->input[0]) &&
                 ((cpuid->input[1] == XEN_CPUID_INPUT_UNUSED) ||
                  (cpuid->input[1] == ctl->input[1])) )
                break;
        }
        
        if ( i == MAX_CPUID_INPUT )
        {
            ret = -ENOENT;
        }
        else
        {
            memcpy(cpuid, ctl, sizeof(cpuid_input_t));
            ret = 0;
        }

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_gettscinfo:
    {
        struct domain *d;
        xen_guest_tsc_info_t info;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d == NULL )
            break;

        domain_pause(d);
        tsc_get_info(d, &info.tsc_mode,
                        &info.elapsed_nsec,
                        &info.gtsc_khz,
                        &info.incarnation);
        if ( copy_to_guest(domctl->u.tsc_info.out_info, &info, 1) )
            ret = -EFAULT;
        else
            ret = 0;
        domain_unpause(d);

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_settscinfo:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d == NULL )
            break;

        domain_pause(d);
        tsc_set_info(d, domctl->u.tsc_info.info.tsc_mode,
                     domctl->u.tsc_info.info.elapsed_nsec,
                     domctl->u.tsc_info.info.gtsc_khz,
                     domctl->u.tsc_info.info.incarnation);
        domain_unpause(d);

        rcu_unlock_domain(d);
        ret = 0;
    }
    break;

    case XEN_DOMCTL_suppress_spurious_page_faults:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d != NULL )
        {
            d->arch.suppress_spurious_page_faults = 1;
            rcu_unlock_domain(d);
            ret = 0;
        }
    }
    break;

    case XEN_DOMCTL_debug_op:
    {
        struct domain *d;
        struct vcpu *v;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d == NULL )
            break;

        ret = -EINVAL;
        if ( (domctl->u.debug_op.vcpu >= d->max_vcpus) ||
             ((v = d->vcpu[domctl->u.debug_op.vcpu]) == NULL) )
            goto debug_op_out;

        ret = -EINVAL;
        if ( !is_hvm_domain(d))
            goto debug_op_out;

        ret = hvm_debug_op(v, domctl->u.debug_op.op);

    debug_op_out:
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_gdbsx_guestmemio:
    {
        struct domain *d;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        domctl->u.gdbsx_guest_memio.remain =
            domctl->u.gdbsx_guest_memio.len;

        ret = gdbsx_guest_mem_io(domctl->domain, &domctl->u.gdbsx_guest_memio);
        if ( !ret && copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;

        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_gdbsx_pausevcpu:
    {
        struct domain *d;
        struct vcpu *v;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = -EBUSY;
        if ( !d->is_paused_by_controller )
        {
            rcu_unlock_domain(d);
            break;
        }
        ret = -EINVAL;
        if ( domctl->u.gdbsx_pauseunp_vcpu.vcpu >= MAX_VIRT_CPUS ||
             (v = d->vcpu[domctl->u.gdbsx_pauseunp_vcpu.vcpu]) == NULL )
        {
            rcu_unlock_domain(d);
            break;
        }
        vcpu_pause(v);
        ret = 0;
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_gdbsx_unpausevcpu:
    {
        struct domain *d;
        struct vcpu *v;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        ret = -EBUSY;
        if ( !d->is_paused_by_controller )
        {
            rcu_unlock_domain(d);
            break;
        }
        ret = -EINVAL;
        if ( domctl->u.gdbsx_pauseunp_vcpu.vcpu >= MAX_VIRT_CPUS ||
             (v = d->vcpu[domctl->u.gdbsx_pauseunp_vcpu.vcpu]) == NULL )
        {
            rcu_unlock_domain(d);
            break;
        }
        if ( !atomic_read(&v->pause_count) )
            printk("WARN: Unpausing vcpu:%d which is not paused\n", v->vcpu_id);
        vcpu_unpause(v);
        ret = 0;
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_gdbsx_domstatus:
    {
        struct domain *d;
        struct vcpu *v;

        ret = -ESRCH;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        domctl->u.gdbsx_domstatus.vcpu_id = -1;
        domctl->u.gdbsx_domstatus.paused = d->is_paused_by_controller;
        if ( domctl->u.gdbsx_domstatus.paused )
        {
            for_each_vcpu ( d, v )
            {
                if ( v->arch.gdbsx_vcpu_event )
                {
                    domctl->u.gdbsx_domstatus.vcpu_id = v->vcpu_id;
                    domctl->u.gdbsx_domstatus.vcpu_ev =
                        v->arch.gdbsx_vcpu_event;
                    v->arch.gdbsx_vcpu_event = 0;
                    break;
                }
            }
        }
        ret = 0;
        if ( copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_setvcpuextstate:
    case XEN_DOMCTL_getvcpuextstate:
    {
        struct xen_domctl_vcpuextstate *evc;
        struct domain *d;
        struct vcpu *v;
        uint32_t offset = 0;
        uint64_t _xfeature_mask = 0;
        uint64_t _xcr0, _xcr0_accum;
        void *receive_buf = NULL, *_xsave_area;

#define PV_XSAVE_SIZE (2 * sizeof(uint64_t) + xsave_cntxt_size)

        evc = &domctl->u.vcpuextstate;

        ret = -ESRCH;

        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d == NULL )
            break;

        ret = xsm_vcpuextstate(d, domctl->cmd);
        if ( ret )
            goto vcpuextstate_out;

        ret = -ESRCH;
        if ( (evc->vcpu >= d->max_vcpus) ||
             ((v = d->vcpu[evc->vcpu]) == NULL) )
            goto vcpuextstate_out;

        if ( domctl->cmd == XEN_DOMCTL_getvcpuextstate )
        {
            if ( !evc->size && !evc->xfeature_mask )
            {
                evc->xfeature_mask = xfeature_mask;
                evc->size = PV_XSAVE_SIZE;
                ret = 0;
                goto vcpuextstate_out;
            }
            if ( evc->size != PV_XSAVE_SIZE ||
                 evc->xfeature_mask != xfeature_mask )
            {
                ret = -EINVAL;
                goto vcpuextstate_out;
            }
            if ( copy_to_guest_offset(domctl->u.vcpuextstate.buffer,
                                      offset, (void *)&v->arch.xcr0,
                                      sizeof(v->arch.xcr0)) )
            {
                ret = -EFAULT;
                goto vcpuextstate_out;
            }
            offset += sizeof(v->arch.xcr0);
            if ( copy_to_guest_offset(domctl->u.vcpuextstate.buffer,
                                      offset, (void *)&v->arch.xcr0_accum,
                                      sizeof(v->arch.xcr0_accum)) )
            {
                ret = -EFAULT;
                goto vcpuextstate_out;
            }
            offset += sizeof(v->arch.xcr0_accum);
            if ( copy_to_guest_offset(domctl->u.vcpuextstate.buffer,
                                      offset, (void *)v->arch.xsave_area,
                                      xsave_cntxt_size) )
            {
                ret = -EFAULT;
                goto vcpuextstate_out;
            }
        }
        else
        {
            ret = -EINVAL;

            _xfeature_mask = evc->xfeature_mask;
            /* xsave context must be restored on compatible target CPUs */
            if ( (_xfeature_mask & xfeature_mask) != _xfeature_mask )
                goto vcpuextstate_out;
            if ( evc->size > PV_XSAVE_SIZE || evc->size < 2 * sizeof(uint64_t) )
                goto vcpuextstate_out;

            receive_buf = xmalloc_bytes(evc->size);
            if ( !receive_buf )
            {
                ret = -ENOMEM;
                goto vcpuextstate_out;
            }
            if ( copy_from_guest_offset(receive_buf, domctl->u.vcpuextstate.buffer,
                                        offset, evc->size) )
            {
                ret = -EFAULT;
                xfree(receive_buf);
                goto vcpuextstate_out;
            }

            _xcr0 = *(uint64_t *)receive_buf;
            _xcr0_accum = *(uint64_t *)(receive_buf + sizeof(uint64_t));
            _xsave_area = receive_buf + 2 * sizeof(uint64_t);

            if ( !(_xcr0 & XSTATE_FP) || _xcr0 & ~xfeature_mask )
            {
                xfree(receive_buf);
                goto vcpuextstate_out;
            }
            if ( (_xcr0 & _xcr0_accum) != _xcr0 )
            {
                xfree(receive_buf);
                goto vcpuextstate_out;
            }

            v->arch.xcr0 = _xcr0;
            v->arch.xcr0_accum = _xcr0_accum;
            memcpy(v->arch.xsave_area, _xsave_area, evc->size - 2 * sizeof(uint64_t) );

            xfree(receive_buf);
        }

        ret = 0;

    vcpuextstate_out:
        rcu_unlock_domain(d);
        if ( (domctl->cmd == XEN_DOMCTL_getvcpuextstate) &&
             copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;
    }
    break;

#ifdef __x86_64__
    case XEN_DOMCTL_mem_event_op:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d != NULL )
        {
            ret = xsm_mem_event(d);
            if ( !ret )
                ret = mem_event_domctl(d, &domctl->u.mem_event_op,
                                       guest_handle_cast(u_domctl, void));
            rcu_unlock_domain(d);
            copy_to_guest(u_domctl, domctl, 1);
        } 
    }
    break;

    case XEN_DOMCTL_mem_sharing_op:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d != NULL )
        {
            ret = xsm_mem_sharing(d);
            if ( !ret )
                ret = mem_sharing_domctl(d, &domctl->u.mem_sharing_op);
            rcu_unlock_domain(d);
        } 
    }
    break;
#endif /* __x86_64__ */

#if P2M_AUDIT
    case XEN_DOMCTL_audit_p2m:
    {
        struct domain *d;

        ret = rcu_lock_remote_target_domain_by_id(domctl->domain, &d);
        if ( ret != 0 )
            break;

        audit_p2m(d,
                  &domctl->u.audit_p2m.orphans,
                  &domctl->u.audit_p2m.m2p_bad,
                  &domctl->u.audit_p2m.p2m_bad);
        rcu_unlock_domain(d);
        if ( copy_to_guest(u_domctl, domctl, 1) ) 
            ret = -EFAULT;
    }
    break;
#endif /* P2M_AUDIT */

    case XEN_DOMCTL_set_access_required:
    {
        struct domain *d;
        struct p2m_domain* p2m;
        
        ret = -EPERM;
        if ( current->domain->domain_id == domctl->domain )
            break;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d != NULL )
        {
            ret = xsm_mem_event(d);
            if ( !ret ) {
                p2m = p2m_get_hostp2m(d);
                p2m->access_required = domctl->u.access_required.access_required;
            }
            rcu_unlock_domain(d);
        } 
    }
    break;

    default:
        ret = iommu_do_domctl(domctl, u_domctl);
        break;
    }

    return ret;
}

#ifdef CONFIG_COMPAT
#define xen_vcpu_guest_context vcpu_guest_context
#define fpu_ctxt fpu_ctxt.x
CHECK_FIELD_(struct, vcpu_guest_context, fpu_ctxt);
#undef fpu_ctxt
#undef xen_vcpu_guest_context
#endif

void arch_get_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
    unsigned int i;
    bool_t compat = is_pv_32on64_domain(v->domain);
#ifdef CONFIG_COMPAT
#define c(fld) (!compat ? (c.nat->fld) : (c.cmp->fld))
#else
#define c(fld) (c.nat->fld)
#endif

    if ( is_hvm_vcpu(v) )
        memset(c.nat, 0, sizeof(*c.nat));
    memcpy(&c.nat->fpu_ctxt, v->arch.fpu_ctxt, sizeof(c.nat->fpu_ctxt));
    c(flags = v->arch.vgc_flags & ~(VGCF_i387_valid|VGCF_in_kernel));
    if ( v->fpu_initialised )
        c(flags |= VGCF_i387_valid);
    if ( !test_bit(_VPF_down, &v->pause_flags) )
        c(flags |= VGCF_online);
    if ( !compat )
    {
        memcpy(&c.nat->user_regs, &v->arch.user_regs, sizeof(c.nat->user_regs));
        if ( !is_hvm_vcpu(v) )
            memcpy(c.nat->trap_ctxt, v->arch.pv_vcpu.trap_ctxt,
                   sizeof(c.nat->trap_ctxt));
    }
#ifdef CONFIG_COMPAT
    else
    {
        XLAT_cpu_user_regs(&c.cmp->user_regs, &v->arch.user_regs);
        for ( i = 0; i < ARRAY_SIZE(c.cmp->trap_ctxt); ++i )
            XLAT_trap_info(c.cmp->trap_ctxt + i,
                           v->arch.pv_vcpu.trap_ctxt + i);
    }
#endif

    for ( i = 0; i < ARRAY_SIZE(v->arch.debugreg); ++i )
        c(debugreg[i] = v->arch.debugreg[i]);

    if ( is_hvm_vcpu(v) )
    {
        struct segment_register sreg;

        c.nat->ctrlreg[0] = v->arch.hvm_vcpu.guest_cr[0];
        c.nat->ctrlreg[2] = v->arch.hvm_vcpu.guest_cr[2];
        c.nat->ctrlreg[3] = v->arch.hvm_vcpu.guest_cr[3];
        c.nat->ctrlreg[4] = v->arch.hvm_vcpu.guest_cr[4];
        hvm_get_segment_register(v, x86_seg_cs, &sreg);
        c.nat->user_regs.cs = sreg.sel;
        hvm_get_segment_register(v, x86_seg_ss, &sreg);
        c.nat->user_regs.ss = sreg.sel;
        hvm_get_segment_register(v, x86_seg_ds, &sreg);
        c.nat->user_regs.ds = sreg.sel;
        hvm_get_segment_register(v, x86_seg_es, &sreg);
        c.nat->user_regs.es = sreg.sel;
        hvm_get_segment_register(v, x86_seg_fs, &sreg);
        c.nat->user_regs.fs = sreg.sel;
        hvm_get_segment_register(v, x86_seg_gs, &sreg);
        c.nat->user_regs.gs = sreg.sel;
    }
    else
    {
        c(ldt_base = v->arch.pv_vcpu.ldt_base);
        c(ldt_ents = v->arch.pv_vcpu.ldt_ents);
        for ( i = 0; i < ARRAY_SIZE(v->arch.pv_vcpu.gdt_frames); ++i )
            c(gdt_frames[i] = v->arch.pv_vcpu.gdt_frames[i]);
#ifdef CONFIG_COMPAT
        BUILD_BUG_ON(ARRAY_SIZE(c.nat->gdt_frames) !=
                     ARRAY_SIZE(c.cmp->gdt_frames));
#endif
        for ( ; i < ARRAY_SIZE(c.nat->gdt_frames); ++i )
            c(gdt_frames[i] = 0);
        c(gdt_ents = v->arch.pv_vcpu.gdt_ents);
        c(kernel_ss = v->arch.pv_vcpu.kernel_ss);
        c(kernel_sp = v->arch.pv_vcpu.kernel_sp);
        for ( i = 0; i < ARRAY_SIZE(v->arch.pv_vcpu.ctrlreg); ++i )
            c(ctrlreg[i] = v->arch.pv_vcpu.ctrlreg[i]);
        c(event_callback_eip = v->arch.pv_vcpu.event_callback_eip);
        c(failsafe_callback_eip = v->arch.pv_vcpu.failsafe_callback_eip);
#ifdef CONFIG_X86_64
        if ( !compat )
        {
            c.nat->syscall_callback_eip = v->arch.pv_vcpu.syscall_callback_eip;
            c.nat->fs_base = v->arch.pv_vcpu.fs_base;
            c.nat->gs_base_kernel = v->arch.pv_vcpu.gs_base_kernel;
            c.nat->gs_base_user = v->arch.pv_vcpu.gs_base_user;
        }
        else
#endif
        {
            c(event_callback_cs = v->arch.pv_vcpu.event_callback_cs);
            c(failsafe_callback_cs = v->arch.pv_vcpu.failsafe_callback_cs);
        }
        c(vm_assist = v->arch.pv_vcpu.vm_assist);

        /* IOPL privileges are virtualised: merge back into returned eflags. */
        BUG_ON((c(user_regs.eflags) & X86_EFLAGS_IOPL) != 0);
        c(user_regs.eflags |= v->arch.pv_vcpu.iopl << 12);

        if ( !is_pv_32on64_domain(v->domain) )
        {
            c.nat->ctrlreg[3] = xen_pfn_to_cr3(
                pagetable_get_pfn(v->arch.guest_table));
#ifdef __x86_64__
            c.nat->ctrlreg[1] =
                pagetable_is_null(v->arch.guest_table_user) ? 0
                : xen_pfn_to_cr3(pagetable_get_pfn(v->arch.guest_table_user));
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

        if ( guest_kernel_mode(v, &v->arch.user_regs) )
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
