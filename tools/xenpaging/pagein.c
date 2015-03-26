/* Trigger a page-in in a separate thread-of-execution to avoid deadlock */
#include <pthread.h>
#include <xc_private.h>
#include "xenpaging.h"

struct page_in_args {
    domid_t dom;
    unsigned long *pagein_queue;
    xc_interface *xch;
};

static struct page_in_args page_in_args;
static unsigned long page_in_request;
static unsigned int page_in_possible;

static pthread_t page_in_thread;
static pthread_cond_t page_in_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t page_in_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *page_in(void *arg)
{
    struct page_in_args *pia = arg;
    void *page;
    int i, num;
    xen_pfn_t gfns[XENPAGING_PAGEIN_QUEUE_SIZE];

    while (1)
    {
        pthread_mutex_lock(&page_in_mutex);
        while (!page_in_request)
            pthread_cond_wait(&page_in_cond, &page_in_mutex);
        num = 0;
        for (i = 0; i < XENPAGING_PAGEIN_QUEUE_SIZE; i++)
        {
            if (!pia->pagein_queue[i])
               continue;
            gfns[num] = pia->pagein_queue[i];
            pia->pagein_queue[i] = 0;
            num++;
        }
        page_in_request = 0;
        pthread_mutex_unlock(&page_in_mutex);

        /* Ignore errors */
        page = xc_map_foreign_pages(pia->xch, pia->dom, PROT_READ, gfns, num);
        if (page)
            munmap(page, PAGE_SIZE * num);
    }
    page_in_possible = 0;
    pthread_exit(NULL);
}

void page_in_trigger(void)
{
    if (!page_in_possible)
        return;

    pthread_mutex_lock(&page_in_mutex);
    page_in_request = 1;
    pthread_mutex_unlock(&page_in_mutex);
    pthread_cond_signal(&page_in_cond);
}

void create_page_in_thread(struct xenpaging *paging)
{
    page_in_args.dom = paging->vm_event.domain_id;
    page_in_args.pagein_queue = paging->pagein_queue;
    page_in_args.xch = paging->xc_handle;
    if (pthread_create(&page_in_thread, NULL, page_in, &page_in_args) == 0)
        page_in_possible = 1;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End: 
 */
