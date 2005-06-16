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
#include <public/sched_ctl.h>

long arch_do_dom0_op(dom0_op_t *op, dom0_op_t *u_dom0_op)
{
    long ret = 0;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    switch ( op->cmd )
    {
    /*
     * NOTE: DOM0_GETMEMLIST has somewhat different semantics on IA64 -
     * it actually allocates and maps pages.
     */
    case DOM0_GETMEMLIST:
    {
        unsigned long i;
        struct domain *d = find_domain_by_id(op->u.getmemlist.domain);
        unsigned long start_page = op->u.getmemlist.max_pfns >> 32;
        unsigned long nr_pages = op->u.getmemlist.max_pfns & 0xffffffff;
        unsigned long pfn;
        unsigned long *buffer = op->u.getmemlist.buffer;
        struct page *page;

        ret = -EINVAL;
        if ( d != NULL )
        {
            ret = 0;

            for ( i = start_page; i < (start_page + nr_pages); i++ )
            {
                page = map_new_domain_page(d, i << PAGE_SHIFT);
                if ( page == NULL )
                {
                    ret = -ENOMEM;
                    break;
                }
                pfn = page_to_pfn(page);
                if ( put_user(pfn, buffer) )
                {
                    ret = -EFAULT;
                    break;
                }
                buffer++;
            }

            op->u.getmemlist.num_pfns = i - start_page;
            copy_to_user(u_dom0_op, op, sizeof(*op));
            
            put_domain(d);
        }
    }
    break;

    default:
        ret = -ENOSYS;

    }

    return ret;
}
