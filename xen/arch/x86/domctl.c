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
#include <asm/processor.h>
#include <public/hvm/e820.h>

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
                ret = -EINVAL;
                break;
            }
     
            for ( j = 0; j < k; j++ )
            {      
                struct page_info *page;
                unsigned long mfn = arr32[j];

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
                    arr32[j] |= type;
                    put_page(page);
                }
                else
                    arr32[j] |= XEN_DOMCTL_PFINFO_XTAB;

            }

            if ( copy_to_guest_offset(domctl->u.getpageframeinfo2.array,
                                      n, arr32, k) )
            {
                ret = -EINVAL;
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

        ret = -EINVAL;
        if ( !is_hvm_domain(d) ) 
            goto sethvmcontext_out;

        ret = -ENOMEM;
        if ( (c.data = xmalloc_bytes(c.size)) == NULL )
            goto sethvmcontext_out;

        ret = -EFAULT;
        if ( copy_from_guest(c.data, domctl->u.hvmcontext.buffer, c.size) != 0)
            goto sethvmcontext_out;

        ret = hvm_load(d, &c);

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

        ret = hvm_save(d, &c);

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

        domctl->u.address_size.size = BITS_PER_GUEST_LONG(d);

        ret = 0;
        rcu_unlock_domain(d);

        if ( copy_to_guest(u_domctl, domctl, 1) )
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
#define c(fld) (!IS_COMPAT(v->domain) ? (c.nat->fld) : (c.cmp->fld))
#else
#define c(fld) (c.nat->fld)
#endif

    if ( !IS_COMPAT(v->domain) )
        memcpy(c.nat, &v->arch.guest_context, sizeof(*c.nat));
#ifdef CONFIG_COMPAT
    else
        XLAT_vcpu_guest_context(c.cmp, &v->arch.guest_context);
#endif

    c(flags &= ~(VGCF_i387_valid|VGCF_in_kernel));
    if ( test_bit(_VCPUF_fpu_initialised, &v->vcpu_flags) )
        c(flags |= VGCF_i387_valid);

    if ( is_hvm_vcpu(v) )
    {
        if ( !IS_COMPAT(v->domain) )
            hvm_store_cpu_guest_regs(v, &c.nat->user_regs, c.nat->ctrlreg);
#ifdef CONFIG_COMPAT
        else
        {
            struct cpu_user_regs user_regs;
            typeof(c.nat->ctrlreg) ctrlreg;
            unsigned i;

            hvm_store_cpu_guest_regs(v, &user_regs, ctrlreg);
            XLAT_cpu_user_regs(&c.cmp->user_regs, &user_regs);
            for ( i = 0; i < ARRAY_SIZE(c.cmp->ctrlreg); ++i )
                c.cmp->ctrlreg[i] = ctrlreg[i];
        }
#endif
    }
    else
    {
        /* IOPL privileges are virtualised: merge back into returned eflags. */
        BUG_ON((c(user_regs.eflags) & EF_IOPL) != 0);
        c(user_regs.eflags |= v->arch.iopl << 12);

        if ( !IS_COMPAT(v->domain) )
        {
            c.nat->ctrlreg[3] = xen_pfn_to_cr3(
                pagetable_get_pfn(v->arch.guest_table));
#ifdef __x86_64__
            if ( !pagetable_is_null(v->arch.guest_table_user) )
                c.nat->ctrlreg[1] = xen_pfn_to_cr3(
                    pagetable_get_pfn(v->arch.guest_table_user));
#endif
        }
#ifdef CONFIG_COMPAT
        else
        {
            l4_pgentry_t *l4e = __va(pagetable_get_paddr(v->arch.guest_table));
            c.cmp->ctrlreg[3] = compat_pfn_to_cr3(l4e_get_pfn(*l4e));
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
