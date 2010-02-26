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
#include <asm/hypercall.h> /* for arch_do_domctl */
#include <xsm/xsm.h>
#include <xen/iommu.h>
#include <asm/mem_event.h>
#include <public/mem_event.h>
#include <asm/mem_sharing.h>

#ifdef XEN_GDBSX_CONFIG                    
#ifdef XEN_KDB_CONFIG
#include "../kdb/include/kdbdefs.h"
#include "../kdb/include/kdbproto.h"
#else
typedef unsigned long kdbva_t;
typedef unsigned char kdbbyt_t;
extern int dbg_rw_mem(kdbva_t, kdbbyt_t *, int, domid_t, int, uint64_t);
#endif
static int 
gdbsx_guest_mem_io(domid_t domid, struct xen_domctl_gdbsx_memio *iop)
{   
    ulong l_uva = (ulong)iop->uva;
    iop->remain = dbg_rw_mem(
        (kdbva_t)iop->gva, (kdbbyt_t *)l_uva, iop->len, domid,
        iop->gwr, iop->pgd3val);
    return (iop->remain ? -EFAULT : 0);
}
#endif  /* XEN_GDBSX_CONFIG */

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
                    unsigned long type = 0, mfn = arr[j];

                    page = mfn_to_page(mfn);

                    if ( unlikely(!mfn_valid(mfn)) )
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
                unsigned long mfn = arr32[j];

                page = mfn_to_page(mfn);

                if ( domctl->cmd == XEN_DOMCTL_getpageframeinfo3)
                    arr32[j] = 0;

                if ( unlikely(!mfn_valid(mfn)) )
                    arr32[j] |= XEN_DOMCTL_PFINFO_XTAB;
                else if ( xsm_getpageframeinfo(page) != 0 )
                    continue;
                else if ( likely(get_page(page, d)) )
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
            rcu_unlock_domain(d);

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
            extern void hvm_acpi_sleep_button(struct domain *d);

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

    case XEN_DOMCTL_get_device_group:
    {
        struct domain *d;
        u32 max_sdevs;
        u8 bus, devfn;
        XEN_GUEST_HANDLE_64(uint32) sdevs;
        int num_sdevs;

        ret = -ENOSYS;
        if ( !iommu_enabled )
            break;

        ret = -EINVAL;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        bus = (domctl->u.get_device_group.machine_bdf >> 16) & 0xff;
        devfn = (domctl->u.get_device_group.machine_bdf >> 8) & 0xff;
        max_sdevs = domctl->u.get_device_group.max_sdevs;
        sdevs = domctl->u.get_device_group.sdev_array;

        num_sdevs = iommu_get_device_group(d, bus, devfn, sdevs, max_sdevs);
        if ( num_sdevs < 0 )
        {
            dprintk(XENLOG_ERR, "iommu_get_device_group() failed!\n");
            ret = -EFAULT;
            domctl->u.get_device_group.num_sdevs = 0;
        }
        else
        {
            ret = 0;
            domctl->u.get_device_group.num_sdevs = num_sdevs;
        }
        if ( copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_test_assign_device:
    {
        u8 bus, devfn;

        ret = -ENOSYS;
        if ( !iommu_enabled )
            break;

        ret = xsm_test_assign_device(domctl->u.assign_device.machine_bdf);
        if ( ret )
            break;

        ret = -EINVAL;
        bus = (domctl->u.assign_device.machine_bdf >> 16) & 0xff;
        devfn = (domctl->u.assign_device.machine_bdf >> 8) & 0xff;

        if ( device_assigned(bus, devfn) )
        {
            gdprintk(XENLOG_ERR, "XEN_DOMCTL_test_assign_device: "
                     "%x:%x.%x already assigned, or non-existent\n",
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

        ret = -ENOSYS;
        if ( !iommu_enabled )
            break;

        ret = -EINVAL;
        if ( unlikely((d = get_domain_by_id(domctl->domain)) == NULL) )
        {
            gdprintk(XENLOG_ERR,
                "XEN_DOMCTL_assign_device: get_domain_by_id() failed\n");
            break;
        }

        ret = xsm_assign_device(d, domctl->u.assign_device.machine_bdf);
        if ( ret )
            goto assign_device_out;

        bus = (domctl->u.assign_device.machine_bdf >> 16) & 0xff;
        devfn = (domctl->u.assign_device.machine_bdf >> 8) & 0xff;

        if ( !iommu_pv_enabled && !is_hvm_domain(d) )
        {
            ret = -ENOSYS;
            goto assign_device_out;
        }

        ret = assign_device(d, bus, devfn);
        if ( ret )
            gdprintk(XENLOG_ERR, "XEN_DOMCTL_assign_device: "
                     "assign device (%x:%x.%x) failed\n",
                     bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

    assign_device_out:
        put_domain(d);
    }
    break;

    case XEN_DOMCTL_deassign_device:
    {
        struct domain *d;
        u8 bus, devfn;

        ret = -ENOSYS;
        if ( !iommu_enabled )
            break;

        ret = -EINVAL;
        if ( unlikely((d = get_domain_by_id(domctl->domain)) == NULL) )
        {
            gdprintk(XENLOG_ERR,
                "XEN_DOMCTL_deassign_device: get_domain_by_id() failed\n");
            break;
        }

        ret = xsm_assign_device(d, domctl->u.assign_device.machine_bdf);
        if ( ret )
            goto deassign_device_out;

        bus = (domctl->u.assign_device.machine_bdf >> 16) & 0xff;
        devfn = (domctl->u.assign_device.machine_bdf >> 8) & 0xff;

        if ( !iommu_pv_enabled && !is_hvm_domain(d) )
        {
            ret = -ENOSYS;
            goto deassign_device_out;
        }
        spin_lock(&pcidevs_lock);
        ret = deassign_device(d, bus, devfn);
        spin_unlock(&pcidevs_lock);
        if ( ret )
            gdprintk(XENLOG_ERR, "XEN_DOMCTL_deassign_device: "
                     "deassign device (%x:%x.%x) failed\n",
                     bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

    deassign_device_out:
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
            gdprintk(XENLOG_ERR, "pt_irq_create_bind failed!\n");

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
            gdprintk(XENLOG_ERR, "pt_irq_destroy_bind failed!\n");

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
        int i;

        ret = -EINVAL;
        if ( (mfn + nr_mfns - 1) < mfn ) /* wrap? */
            break;

        ret = -ESRCH;
        if ( unlikely((d = rcu_lock_domain_by_id(domctl->domain)) == NULL) )
            break;

        ret = -EPERM;
        if ( !IS_PRIV(current->domain) &&
             !iomem_access_permitted(current->domain, mfn, mfn + nr_mfns - 1) )
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

        ret = -EPERM;
        if ( !IS_PRIV(current->domain) &&
             !ioports_access_permitted(current->domain, fmp, fmp + np - 1) )
            break;

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

#ifdef XEN_GDBSX_CONFIG
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
#endif /* XEN_GDBSX_CONFIG */

    case XEN_DOMCTL_mem_event_op:
    {
        struct domain *d;

        ret = -ESRCH;
        d = rcu_lock_domain_by_id(domctl->domain);
        if ( d != NULL )
        {
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
            ret = mem_sharing_domctl(d, &domctl->u.mem_sharing_op);
            rcu_unlock_domain(d);
            copy_to_guest(u_domctl, domctl, 1);
        } 
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
        struct segment_register sreg;
        memset(c.nat->ctrlreg, 0, sizeof(c.nat->ctrlreg));
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
        /* IOPL privileges are virtualised: merge back into returned eflags. */
        BUG_ON((c(user_regs.eflags) & X86_EFLAGS_IOPL) != 0);
        c(user_regs.eflags |= v->arch.iopl << 12);

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
