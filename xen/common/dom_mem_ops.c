/******************************************************************************
 * dom_mem_ops.c
 *
 * Code to handle memory related requests from domains eg. balloon driver.
 *
 * Copyright (c) 2003, B Dragovic & K A Fraser.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <hypervisor-ifs/dom_mem_ops.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/domain_page.h>

static long alloc_dom_mem(struct task_struct *p, reservation_increase_t op)
{
    struct pfn_info  *page;
    unsigned long     mpfn;   /* machine frame number of current page */
    void             *va;     /* Xen-usable mapping of current page */
    unsigned long     i;

    for ( i = 0; i < op.size; i++ )
    {
        /* Leave some slack pages; e.g., for the network. */
        if ( unlikely(free_pfns < (SLACK_DOMAIN_MEM_KILOBYTES >> 
                                   (PAGE_SHIFT-10))) )
        {
            DPRINTK("Not enough slack: %u %u\n",
                    free_pfns,
                    SLACK_DOMAIN_MEM_KILOBYTES >> (PAGE_SHIFT-10));
            break;
        }

        /* NB. 'alloc_domain_page' does limit checking on pages per domain. */
        if ( unlikely((page = alloc_domain_page(p)) == NULL) )
        {
            DPRINTK("Could not allocate a frame\n");
            break;
        }

        /* Inform the domain of the new page's machine address. */ 
        mpfn = (unsigned long)(page - frame_table);
        copy_to_user(op.pages, &mpfn, sizeof(mpfn));
        op.pages++; 

        /* Zero out the page to prevent information leakage. */
        va = map_domain_mem(mpfn << PAGE_SHIFT);
        memset(va, 0, PAGE_SIZE);
        unmap_domain_mem(va);
    }

    return i;
}
    
static long free_dom_mem(struct task_struct *p, reservation_decrease_t op)
{
    struct pfn_info  *page;
    unsigned long     mpfn;   /* machine frame number of current page */
    unsigned long     i;
    long              rc = 0;
    int               need_flush = 0;

    for ( i = 0; i < op.size; i++ )
    {
        copy_from_user(&mpfn, op.pages, sizeof(mpfn));
        op.pages++;
        if ( mpfn >= max_page )
        {
            DPRINTK("Domain %llu page number out of range (%08lx>=%08lx)\n", 
                    p->domain, mpfn, max_page);
            rc = -EINVAL;
            goto out;
        }

        page = &frame_table[mpfn];
        if ( unlikely(!get_page(page, p)) )
        {
            DPRINTK("Bad page free for domain %llu\n", p->domain);
            rc = -EINVAL;
            goto out;
        }

        if ( test_and_clear_bit(_PGC_guest_pinned, &page->count_and_flags) )
            put_page_and_type(page);

        if ( test_and_clear_bit(_PGC_allocated, &page->count_and_flags) )
            put_page(page);

        put_page(page);
    }

 out:
    if ( need_flush )
    {
        __flush_tlb();
        perfc_incr(need_flush_tlb_flush);
    }

    return rc ? rc : op.size;
}
    
long do_dom_mem_op(dom_mem_op_t *mem_op)
{
    dom_mem_op_t dmop;
    unsigned long ret;

    if ( copy_from_user(&dmop, mem_op, sizeof(dom_mem_op_t)) )
        return -EFAULT;

    switch ( dmop.op )
    {
    case MEMOP_RESERVATION_INCREASE:
        ret = alloc_dom_mem(current, dmop.u.increase);
        break;

    case MEMOP_RESERVATION_DECREASE:
        ret = free_dom_mem(current, dmop.u.decrease);
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;    
}
