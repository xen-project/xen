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
#include <public/domctl.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <asm/msr.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <asm/shadow.h>
#include <asm/irq.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/processor.h>

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
        d = find_domain_by_id(domctl->domain);
        if ( d != NULL )
        {
            ret = shadow_domctl(d, &domctl->u.shadow_op, u_domctl);
            put_domain(d);
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
        if ( unlikely((d = find_domain_by_id(domctl->domain)) == NULL) )
            break;

        if ( np == 0 )
            ret = 0;
        else if ( domctl->u.ioport_permission.allow_access )
            ret = ioports_permit_access(d, fp, fp + np - 1);
        else
            ret = ioports_deny_access(d, fp, fp + np - 1);

        put_domain(d);
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
             unlikely((d = find_domain_by_id(dom)) == NULL) )
            break;

        page = mfn_to_page(mfn);

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

        put_domain(d);

        copy_to_guest(u_domctl, domctl, 1);
    }
    break;

    case XEN_DOMCTL_getpageframeinfo2:
    {
#define GPF2_BATCH (PAGE_SIZE / sizeof(long))
        int n,j;
        int num = domctl->u.getpageframeinfo2.num;
        domid_t dom = domctl->domain;
        struct domain *d;
        unsigned long *l_arr;
        ret = -ESRCH;

        if ( unlikely((d = find_domain_by_id(dom)) == NULL) )
            break;

        if ( unlikely(num > 1024) )
        {
            ret = -E2BIG;
            put_domain(d);
            break;
        }

        l_arr = alloc_xenheap_page();
 
        ret = 0;
        for ( n = 0; n < num; )
        {
            int k = ((num-n)>GPF2_BATCH)?GPF2_BATCH:(num-n);

            if ( copy_from_guest_offset(l_arr,
                                        domctl->u.getpageframeinfo2.array,
                                        n, k) )
            {
                ret = -EINVAL;
                break;
            }
     
            for ( j = 0; j < k; j++ )
            {      
                struct page_info *page;
                unsigned long mfn = l_arr[j];

                page = mfn_to_page(mfn);

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
                    l_arr[j] |= type;
                    put_page(page);
                }
                else
                    l_arr[j] |= XEN_DOMCTL_PFINFO_XTAB;

            }

            if ( copy_to_guest_offset(domctl->u.getpageframeinfo2.array,
                                      n, l_arr, k) )
            {
                ret = -EINVAL;
                break;
            }

            n += k;
        }

        free_xenheap_page(l_arr);

        put_domain(d);
    }
    break;

    case XEN_DOMCTL_getmemlist:
    {
        int i;
        struct domain *d = find_domain_by_id(domctl->domain);
        unsigned long max_pfns = domctl->u.getmemlist.max_pfns;
        unsigned long mfn;
        struct list_head *list_ent;

        ret = -EINVAL;
        if ( d != NULL )
        {
            ret = 0;

            spin_lock(&d->page_alloc_lock);
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

            put_domain(d);
        }
    }
    break;

    case XEN_DOMCTL_hypercall_init:
    {
        struct domain *d = find_domain_by_id(domctl->domain);
        unsigned long gmfn = domctl->u.hypercall_init.gmfn;
        unsigned long mfn;
        void *hypercall_page;

        ret = -ESRCH;
        if ( unlikely(d == NULL) )
            break;

        mfn = gmfn_to_mfn(d, gmfn);

        ret = -EACCES;
        if ( !mfn_valid(mfn) ||
             !get_page_and_type(mfn_to_page(mfn), d, PGT_writable_page) )
        {
            put_domain(d);
            break;
        }

        ret = 0;

        hypercall_page = map_domain_page(mfn);
        hypercall_page_initialise(d, hypercall_page);
        unmap_domain_page(hypercall_page);

        put_page_and_type(mfn_to_page(mfn));

        put_domain(d);
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

void arch_getdomaininfo_ctxt(
    struct vcpu *v, struct vcpu_guest_context *c)
{
    memcpy(c, &v->arch.guest_context, sizeof(*c));

    if ( hvm_guest(v) )
    {
        hvm_store_cpu_guest_regs(v, &c->user_regs, c->ctrlreg);
    }
    else
    {
        /* IOPL privileges are virtualised: merge back into returned eflags. */
        BUG_ON((c->user_regs.eflags & EF_IOPL) != 0);
        c->user_regs.eflags |= v->arch.iopl << 12;
    }

    c->flags = 0;
    if ( test_bit(_VCPUF_fpu_initialised, &v->vcpu_flags) )
        c->flags |= VGCF_I387_VALID;
    if ( guest_kernel_mode(v, &v->arch.guest_context.user_regs) )
        c->flags |= VGCF_IN_KERNEL;
    if ( hvm_guest(v) )
        c->flags |= VGCF_HVM_GUEST;

    c->ctrlreg[3] = xen_pfn_to_cr3(pagetable_get_pfn(v->arch.guest_table));

    c->vm_assist = v->domain->vm_assist;
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
