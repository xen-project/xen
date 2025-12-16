#include <xen/event.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/spinlock.h>

static int _paging_ret_to_domheap(struct domain *d)
{
    struct page_info *page;

    ASSERT(spin_is_locked(&d->arch.paging.lock));

    /* Return memory to domheap. */
    page = page_list_remove_head(&d->arch.paging.freelist);
    if( page )
    {
        d->arch.paging.total_pages--;
        free_domheap_page(page);
    }
    else
    {
        printk(XENLOG_ERR
               "failed to free pages, P2M freelist is empty\n");
        return -ENOMEM;
    }

    return 0;
}

static int _paging_add_to_freelist(struct domain *d)
{
    struct page_info *page;

    ASSERT(spin_is_locked(&d->arch.paging.lock));

    /* Need to allocate more memory from domheap */
    page = alloc_domheap_page(d, MEMF_no_owner);
    if ( page == NULL )
    {
        printk(XENLOG_ERR "failed to allocate pages\n");
        return -ENOMEM;
    }
    d->arch.paging.total_pages++;
    page_list_add_tail(page, &d->arch.paging.freelist);

    return 0;
}

int paging_freelist_adjust(struct domain *d, unsigned long pages,
                           bool *preempted)
{
    ASSERT(spin_is_locked(&d->arch.paging.lock));

    for ( ; ; )
    {
        int rc = 0;

        if ( d->arch.paging.total_pages < pages )
            rc = _paging_add_to_freelist(d);
        else if ( d->arch.paging.total_pages > pages )
            rc = _paging_ret_to_domheap(d);
        else
            break;

        if ( rc )
            return rc;

        /* Check to see if we need to yield and try again */
        if ( preempted && general_preempt_check() )
        {
            *preempted = true;
            return -ERESTART;
        }
    }

    return 0;
}

int paging_refill_from_domheap(struct domain *d, unsigned int nr_pages)
{
    ASSERT(spin_is_locked(&d->arch.paging.lock));

    for ( unsigned int i = 0; i < nr_pages; i++ )
    {
        int rc = _paging_add_to_freelist(d);

        if ( rc )
            return rc;
    }

    return 0;
}

int paging_ret_to_domheap(struct domain *d, unsigned int nr_pages)
{
    ASSERT(spin_is_locked(&d->arch.paging.lock));

    if ( d->arch.paging.total_pages < nr_pages )
        return false;

    for ( unsigned int i = 0; i < nr_pages; i++ )
    {
        int rc = _paging_ret_to_domheap(d);

        if ( rc )
            return rc;
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
