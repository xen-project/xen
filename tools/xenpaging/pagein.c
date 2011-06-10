/* Trigger a page-in in a separate thread-of-execution to avoid deadlock */
#include <pthread.h>
#include "xc_private.h"

struct page_in_args {
    domid_t dom;
    xc_interface *xch;
};

static struct page_in_args page_in_args;
static unsigned long page_in_gfn;
static unsigned int page_in_possible;

static pthread_t page_in_thread;
static pthread_cond_t page_in_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t page_in_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *page_in(void *arg)
{
    struct page_in_args *pia = arg;
    void *page;
    xen_pfn_t gfn;

    while (1)
    {
        pthread_mutex_lock(&page_in_mutex);
        while (!page_in_gfn)
            pthread_cond_wait(&page_in_cond, &page_in_mutex);
        gfn = page_in_gfn;
        page_in_gfn = 0;
        pthread_mutex_unlock(&page_in_mutex);

        /* Ignore errors */
        page = xc_map_foreign_pages(pia->xch, pia->dom, PROT_READ, &gfn, 1);
        if (page)
            munmap(page, PAGE_SIZE);
    }
    page_in_possible = 0;
    pthread_exit(NULL);
}

void page_in_trigger(unsigned long gfn)
{
    if (!page_in_possible)
        return;

    pthread_mutex_lock(&page_in_mutex);
    page_in_gfn = gfn;
    pthread_mutex_unlock(&page_in_mutex);
    pthread_cond_signal(&page_in_cond);
}

void create_page_in_thread(domid_t domain_id, xc_interface *xch)
{
    page_in_args.dom = domain_id;
    page_in_args.xch = xch;
    if (pthread_create(&page_in_thread, NULL, page_in, &page_in_args) == 0)
        page_in_possible = 1;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End: 
 */
