#include <xen/event.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/spinlock.h>

int paging_freelist_adjust(struct domain *d, unsigned long pages,
                           bool *preempted)
{
    struct page_info *pg;

    ASSERT(spin_is_locked(&d->arch.paging.lock));

    for ( ; ; )
    {
        if ( d->arch.paging.total_pages < pages )
        {
            /* Need to allocate more memory from domheap */
            pg = alloc_domheap_page(d, MEMF_no_owner);
            if ( pg == NULL )
            {
                printk(XENLOG_ERR "Failed to allocate pages.\n");
                return -ENOMEM;
            }
            ACCESS_ONCE(d->arch.paging.total_pages)++;
            page_list_add_tail(pg, &d->arch.paging.freelist);
        }
        else if ( d->arch.paging.total_pages > pages )
        {
            /* Need to return memory to domheap */
            pg = page_list_remove_head(&d->arch.paging.freelist);
            if ( pg )
            {
                ACCESS_ONCE(d->arch.paging.total_pages)--;
                free_domheap_page(pg);
            }
            else
            {
                printk(XENLOG_ERR
                       "Failed to free pages, freelist is empty.\n");
                return -ENOMEM;
            }
        }
        else
            break;

        /* Check to see if we need to yield and try again */
        if ( preempted && general_preempt_check() )
        {
            *preempted = true;
            return -ERESTART;
        }
    }

    return 0;
}

/* Domain paging struct initialization. */
int paging_domain_init(struct domain *d)
{
    spin_lock_init(&d->arch.paging.lock);
    INIT_PAGE_LIST_HEAD(&d->arch.paging.freelist);

    return 0;
}
