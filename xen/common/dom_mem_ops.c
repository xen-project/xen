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
    struct pfn_info *page;
    unsigned long    i;

    /* Leave some slack pages; e.g., for the network. */
    if ( unlikely(free_pfns < (op.size + (SLACK_DOMAIN_MEM_KILOBYTES >> 
                                          (PAGE_SHIFT-10)))) )
    {
        DPRINTK("Not enough slack: %u %u\n",
                free_pfns,
                SLACK_DOMAIN_MEM_KILOBYTES >> (PAGE_SHIFT-10));
        return 0;
    }

    for ( i = 0; i < op.size; i++ )
    {
        /* NB. 'alloc_domain_page' does limit-checking on pages per domain. */
        if ( unlikely((page = alloc_domain_page(p)) == NULL) )
        {
            DPRINTK("Could not allocate a frame\n");
            break;
        }

        /* Inform the domain of the new page's machine address. */ 
        if ( unlikely(put_user(page_to_pfn(page), &op.pages[i]) != 0) )
            break;
    }

    return i;
}
    
static long free_dom_mem(struct task_struct *p, reservation_decrease_t op)
{
    struct pfn_info *page;
    unsigned long    i, mpfn;
    long             rc = 0;

    for ( i = 0; i < op.size; i++ )
    {
        if ( unlikely(get_user(mpfn, &op.pages[i]) != 0) )
            break;

        if ( unlikely(mpfn >= max_page) )
        {
            DPRINTK("Domain %llu page number out of range (%08lx>=%08lx)\n", 
                    p->domain, mpfn, max_page);
            rc = -EINVAL;
            break;
        }

        page = &frame_table[mpfn];
        if ( unlikely(!get_page(page, p)) )
        {
            DPRINTK("Bad page free for domain %llu\n", p->domain);
            rc = -EINVAL;
            break;
        }

        if ( test_and_clear_bit(_PGC_guest_pinned, &page->count_and_flags) )
            put_page_and_type(page);

        if ( test_and_clear_bit(_PGC_allocated, &page->count_and_flags) )
            put_page(page);

        put_page(page);
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
