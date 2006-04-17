/******************************************************************************
 * Arch-specific dom0_ops.c
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <public/dom0_ops.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/pdb.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/guest_access.h>
#include <public/sched_ctl.h>
#include <asm/vmx.h>

long arch_do_dom0_op(dom0_op_t *op, GUEST_HANDLE(dom0_op_t) u_dom0_op)
{
    long ret = 0;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    switch ( op->cmd )
    {
    case DOM0_GETPAGEFRAMEINFO:
    {
        struct page_info *page;
        unsigned long mfn = op->u.getpageframeinfo.mfn;
        domid_t dom = op->u.getpageframeinfo.domain;
        struct domain *d;

        ret = -EINVAL;

        if ( unlikely(!mfn_valid(mfn)) || 
             unlikely((d = find_domain_by_id(dom)) == NULL) )
            break;

        page = mfn_to_page(mfn);

        if ( likely(get_page(page, d)) )
        {
            ret = 0;

            op->u.getpageframeinfo.type = NOTAB;

            if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
            {
                switch ( page->u.inuse.type_info & PGT_type_mask )
                {
                default:
                    panic("No such page type\n");
                    break;
                }
            }
            
            put_page(page);
        }

        put_domain(d);

        copy_to_guest(u_dom0_op, op, 1);
    }
    break;

    case DOM0_GETPAGEFRAMEINFO2:
    {
#define GPF2_BATCH 128
        int n,j;
        int num = op->u.getpageframeinfo2.num;
        domid_t dom = op->u.getpageframeinfo2.domain;
        struct domain *d;
        unsigned long *l_arr;
        ret = -ESRCH;

        if ( unlikely((d = find_domain_by_id(dom)) == NULL) )
            break;

        if ( unlikely(num > 1024) )
        {
            ret = -E2BIG;
            break;
        }

        l_arr = (unsigned long *)alloc_xenheap_page();
 
        ret = 0;
        for( n = 0; n < num; )
        {
            int k = ((num-n)>GPF2_BATCH)?GPF2_BATCH:(num-n);

            if ( copy_from_guest_offset(l_arr, op->u.getpageframeinfo2.array,
                                        n, k) )
            {
                ret = -EINVAL;
                break;
            }
     
            for( j = 0; j < k; j++ )
            {      
                struct page_info *page;
                unsigned long mfn = l_arr[j];

                if ( unlikely(mfn >= max_page) )
                    goto e2_err;

                page = mfn_to_page(mfn);
  
                if ( likely(get_page(page, d)) )
                {
                    unsigned long type = 0;

                    switch( page->u.inuse.type_info & PGT_type_mask )
                    {
                    default:
                        panic("No such page type\n");
                        break;
                    }

                    if ( page->u.inuse.type_info & PGT_pinned )
                        type |= LPINTAB;
                    l_arr[j] |= type;
                    put_page(page);
                }
                else
                {
                e2_err:
                    l_arr[j] |= XTAB;
                }

            }

            if ( copy_to_guest_offset(op->u.getpageframeinfo2.array,
                                      n, l_arr, k) )
            {
                ret = -EINVAL;
                break;
            }

            n += j;
        }

        free_xenheap_page((void *) l_arr);

        put_domain(d);
    }
    break;
    /*
     * NOTE: DOM0_GETMEMLIST has somewhat different semantics on IA64 -
     * it actually allocates and maps pages.
     */
    case DOM0_GETMEMLIST:
    {
        unsigned long i = 0;
        struct domain *d = find_domain_by_id(op->u.getmemlist.domain);
        unsigned long start_page = op->u.getmemlist.max_pfns >> 32;
        unsigned long nr_pages = op->u.getmemlist.max_pfns & 0xffffffff;
        unsigned long mfn;
        struct list_head *list_ent;

        ret = -EINVAL;
        if ( d != NULL )
        {
            ret = 0;

            list_ent = d->page_list.next;
            while ( (i != start_page) && (list_ent != &d->page_list)) {
                mfn = page_to_mfn(list_entry(
                    list_ent, struct page_info, list));
                i++;
                list_ent = mfn_to_page(mfn)->list.next;
            }

            if (i == start_page)
            {
                while((i < (start_page + nr_pages)) &&
                      (list_ent != &d->page_list))
                {
                    mfn = page_to_mfn(list_entry(
                        list_ent, struct page_info, list));

                    if ( copy_to_guest_offset(op->u.getmemlist.buffer,
                                          i - start_page, &mfn, 1) )
                    {
                        ret = -EFAULT;
                        break;
                    }
                    i++;
                    list_ent = mfn_to_page(mfn)->list.next;
                }
            } else
                ret = -ENOMEM;

            op->u.getmemlist.num_pfns = i - start_page;
            copy_to_guest(u_dom0_op, op, 1);
            
            put_domain(d);
        }
    }
    break;

    case DOM0_PHYSINFO:
    {
        dom0_physinfo_t *pi = &op->u.physinfo;

        pi->threads_per_core =
            cpus_weight(cpu_sibling_map[0]);
        pi->cores_per_socket =
            cpus_weight(cpu_core_map[0]) / pi->threads_per_core;
        pi->sockets_per_node = 
            num_online_cpus() / cpus_weight(cpu_core_map[0]);
        pi->nr_nodes         = 1;
        pi->total_pages      = 99;  // FIXME
        pi->free_pages       = avail_domheap_pages();
        pi->cpu_khz          = local_cpu_data->proc_freq / 1000;
        memset(pi->hw_cap, 0, sizeof(pi->hw_cap));
        //memcpy(pi->hw_cap, boot_cpu_data.x86_capability, NCAPINTS*4);
        ret = 0;
        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;
    }
    break;

    default:
        printf("arch_do_dom0_op: unrecognized dom0 op: %d!!!\n",op->cmd);
        ret = -ENOSYS;

    }

    return ret;
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
