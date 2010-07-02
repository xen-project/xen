/******************************************************************************
 * tools/xenpaging/xenpaging.c
 *
 * Domain paging. 
 * Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>
#include <xc_private.h>

#include <xen/mem_event.h>

#include "bitops.h"
#include "spinlock.h"
#include "file_ops.h"
#include "xc.h"

#include "policy.h"
#include "xenpaging.h"


#if 0
#undef DPRINTF
#define DPRINTF(...) ((void)0)
#endif


static void *init_page(void)
{
    void *buffer;
    int ret;

    /* Allocated page memory */
    ret = posix_memalign(&buffer, PAGE_SIZE, PAGE_SIZE);
    if ( ret != 0 )
        goto out_alloc;

    /* Lock buffer in memory so it can't be paged out */
    ret = mlock(buffer, PAGE_SIZE);
    if ( ret != 0 )
        goto out_lock;

    return buffer;

 out_init:
    munlock(buffer, PAGE_SIZE);
 out_lock:
    free(buffer);
 out_alloc:
    return NULL;
}

xenpaging_t *xenpaging_init(xc_interface **xch_r, domid_t domain_id)
{
    xenpaging_t *paging;
    xc_interface *xch;
    int rc;

    xch = xc_interface_open(0,0,0);
    if ( !xch ) return NULL;

    DPRINTF("xenpaging init\n");
    *xch_r = xch;

    /* Allocate memory */
    paging = malloc(sizeof(xenpaging_t));
    memset(paging, 0, sizeof(xenpaging_t));

    /* Open connection to xen */
    paging->xc_handle = xch;

    /* Set domain id */
    paging->mem_event.domain_id = domain_id;

    /* Initialise shared page */
    paging->mem_event.shared_page = init_page();
    if ( paging->mem_event.shared_page == NULL )
    {
        ERROR("Error initialising shared page");
        goto err;
    }

    /* Initialise ring page */
    paging->mem_event.ring_page = init_page();
    if ( paging->mem_event.ring_page == NULL )
    {
        ERROR("Error initialising shared page");
        goto err;
    }

    /* Initialise ring */
    SHARED_RING_INIT((mem_event_sring_t *)paging->mem_event.ring_page);
    BACK_RING_INIT(&paging->mem_event.back_ring,
                   (mem_event_sring_t *)paging->mem_event.ring_page,
                   PAGE_SIZE);

    /* Initialise lock */
    mem_event_ring_lock_init(&paging->mem_event);
    
    /* Initialise Xen */
    rc = xc_mem_event_enable(paging->xc_handle, paging->mem_event.domain_id,
                             paging->mem_event.shared_page,
                             paging->mem_event.ring_page);
    if ( rc != 0 )
    {
        ERROR("Error initialising shared page");
        goto err;
    }

    /* Open event channel */
    paging->mem_event.xce_handle = xc_evtchn_open();
    if ( paging->mem_event.xce_handle < 0 )
    {
        ERROR("Failed to open event channel");
        goto err;
    }

    /* Bind event notification */
    rc = xc_evtchn_bind_interdomain(paging->mem_event.xce_handle,
                                    paging->mem_event.domain_id,
                                    paging->mem_event.shared_page->port);
    if ( rc < 0 )
    {
        ERROR("Failed to bind event channel");
        goto err;
    }

    paging->mem_event.port = rc;

    /* Get platform info */
    paging->platform_info = malloc(sizeof(xc_platform_info_t));
    if ( paging->platform_info == NULL )
    {
        ERROR("Error allocating memory for platform info");
        goto err;
    }

    rc = xc_get_platform_info(paging->xc_handle, domain_id,
                              paging->platform_info);
    if ( rc != 1 )
    {
        ERROR("Error getting platform info");
        goto err;
    }

    /* Get domaininfo */
    paging->domain_info = malloc(sizeof(xc_domaininfo_t));
    if ( paging->domain_info == NULL )
    {
        ERROR("Error allocating memory for domain info");
        goto err;
    }

    rc = xc_domain_getinfolist(paging->xc_handle, domain_id, 1,
                               paging->domain_info);
    if ( rc != 1 )
    {
        ERROR("Error getting domain info");
        goto err;
    }

    /* Allocate bitmap for tracking pages that have been paged out */
    paging->bitmap_size = (paging->domain_info->max_pages + BITS_PER_LONG) &
                          ~(BITS_PER_LONG - 1);

    rc = alloc_bitmap(&paging->bitmap, paging->bitmap_size);
    if ( rc != 0 )
    {
        ERROR("Error allocating bitmap");
        goto err;
    }
    DPRINTF("max_pages = %"PRIx64"\n", paging->domain_info->max_pages);

    /* Initialise policy */
    rc = policy_init(paging);
    if ( rc != 0 )
    {
        ERROR("Error initialising policy");
        goto err;
    }

    return paging;

 err:
    if ( paging->bitmap )
        free(paging->bitmap);
    if ( paging->platform_info )
        free(paging->platform_info);
    if ( paging )
        free(paging);

    return NULL;
}

int xenpaging_teardown(xc_interface *xch, xenpaging_t *paging)
{
    int rc;

    if ( paging == NULL )
        return 0;

    /* Tear down domain paging in Xen */
    rc = xc_mem_event_disable(paging->xc_handle, paging->mem_event.domain_id);
    if ( rc != 0 )
    {
        ERROR("Error tearing down domain paging in xen");
        goto err;
    }

    /* Unbind VIRQ */
    rc = xc_evtchn_unbind(paging->mem_event.xce_handle, paging->mem_event.port);
    if ( rc != 0 )
    {
        ERROR("Error unbinding event port");
        goto err;
    }
    paging->mem_event.port = -1;

    /* Close event channel */
    rc = xc_evtchn_close(paging->mem_event.xce_handle);
    if ( rc != 0 )
    {
        ERROR("Error closing event channel");
        goto err;
    }
    paging->mem_event.xce_handle = -1;
    
    /* Close connection to Xen */
    rc = xc_interface_close(paging->xc_handle);
    if ( rc != 0 )
    {
        ERROR("Error closing connection to xen");
        goto err;
    }
    paging->xc_handle = NULL;

    return 0;

 err:
    return -1;
}

static int get_request(mem_event_t *mem_event, mem_event_request_t *req)
{
    mem_event_back_ring_t *back_ring;
    RING_IDX req_cons;

    mem_event_ring_lock(mem_event);

    back_ring = &mem_event->back_ring;
    req_cons = back_ring->req_cons;

    /* Copy request */
    memcpy(req, RING_GET_REQUEST(back_ring, req_cons), sizeof(*req));
    req_cons++;

    /* Update ring */
    back_ring->req_cons = req_cons;
    back_ring->sring->req_event = req_cons + 1;

    mem_event_ring_unlock(mem_event);

    return 0;
}

static int put_response(mem_event_t *mem_event, mem_event_response_t *rsp)
{
    mem_event_back_ring_t *back_ring;
    RING_IDX rsp_prod;

    mem_event_ring_lock(mem_event);

    back_ring = &mem_event->back_ring;
    rsp_prod = back_ring->rsp_prod_pvt;

    /* Copy response */
    memcpy(RING_GET_RESPONSE(back_ring, rsp_prod), rsp, sizeof(*rsp));
    rsp_prod++;

    /* Update ring */
    back_ring->rsp_prod_pvt = rsp_prod;
    RING_PUSH_RESPONSES(back_ring);

    mem_event_ring_unlock(mem_event);

    return 0;
}

int xenpaging_evict_page(xc_interface *xch, xenpaging_t *paging,
                         xenpaging_victim_t *victim, int fd, int i)
{
    void *page;
    unsigned long gfn;
    int ret;

    DECLARE_DOMCTL;

    /* Map page */
    gfn = victim->gfn;
    ret = -EFAULT;
    page = xc_map_foreign_pages(paging->xc_handle, victim->domain_id,
                                PROT_READ | PROT_WRITE, &gfn, 1);
    if ( page == NULL )
    {
        ERROR("Error mapping page");
        goto out;
    }

    /* Copy page */
    ret = write_page(fd, page, i);
    if ( ret != 0 )
    {
        munmap(page, PAGE_SIZE);
        ERROR("Error copying page");
        goto out;
    }

    /* Clear page */
    memset(page, 0, PAGE_SIZE);

    munmap(page, PAGE_SIZE);

    /* Tell Xen to evict page */
    ret = xc_mem_paging_evict(paging->xc_handle, paging->mem_event.domain_id,
                              victim->gfn);
    if ( ret != 0 )
    {
        ERROR("Error evicting page");
        goto out;
    }

    /* Notify policy of page being paged in */
    policy_notify_paged_in(paging->mem_event.domain_id, victim->gfn);

 out:
    return ret;
}

int xenpaging_resume_page(xenpaging_t *paging, mem_event_response_t *rsp)
{
    int ret;

    /* Put the page info on the ring */
    ret = put_response(&paging->mem_event, rsp);
    if ( ret != 0 )
        goto out;

    /* Notify policy of page being paged in */
    policy_notify_paged_in(paging->mem_event.domain_id, rsp->gfn);

    /* Tell Xen page is ready */
    ret = xc_mem_paging_resume(paging->xc_handle, paging->mem_event.domain_id,
                               rsp->gfn);
    ret = xc_evtchn_notify(paging->mem_event.xce_handle,
                           paging->mem_event.port);

 out:
    return ret;
}

static int xenpaging_populate_page(
    xc_interface *xch, xenpaging_t *paging,
    uint64_t *gfn, int fd, int i)
{
    unsigned long _gfn;
    void *page;
    int ret;

    /* Tell Xen to allocate a page for the domain */
    ret = xc_mem_paging_prep(paging->xc_handle, paging->mem_event.domain_id,
                             *gfn);
    if ( ret != 0 )
    {
        ERROR("Error preparing for page in");
        goto out_map;
    }

    /* Map page */
    ret = -EFAULT;
    _gfn = *gfn;
    page = xc_map_foreign_pages(paging->xc_handle, paging->mem_event.domain_id,
                                PROT_READ | PROT_WRITE, &_gfn, 1);
    *gfn = _gfn;
    if ( page == NULL )
    {
        ERROR("Error mapping page: page is null");
        goto out_map;
    }

    /* Read page */
    ret = read_page(fd, page, i);
    if ( ret != 0 )
    {
        ERROR("Error reading page");
        goto out;
    }

 out:
    munmap(page, PAGE_SIZE);
 out_map:
    return ret;
}

static int evict_victim(xc_interface *xch, xenpaging_t *paging, domid_t domain_id,
                        xenpaging_victim_t *victim, int fd, int i)
{
    int j = 0;
    int ret;

    do
    {
        ret = policy_choose_victim(xch, paging, domain_id, victim);
        if ( ret != 0 )
        {
            ERROR("Error choosing victim");
            goto out;
        }

        ret = xc_mem_paging_nominate(paging->xc_handle,
                                     paging->mem_event.domain_id, victim->gfn);
        if ( ret == 0 )
            ret = xenpaging_evict_page(xch, paging, victim, fd, i);
        else
        {
            if ( j++ % 1000 == 0 )
                if ( xc_mem_paging_flush_ioemu_cache(domain_id) )
                    ERROR("Error flushing ioemu cache");
        }
    }
    while ( ret );

    if ( test_and_set_bit(victim->gfn, paging->bitmap) )
        ERROR("Page has been evicted before");

    ret = 0;

 out:
    return ret;
}

int main(int argc, char *argv[])
{
    domid_t domain_id;
    int num_pages;
    xenpaging_t *paging;
    xenpaging_victim_t *victims;
    mem_event_request_t req;
    mem_event_response_t rsp;
    int i;
    int rc = -1;
    int rc1;
    xc_interface *xch;

    int open_flags = O_CREAT | O_TRUNC | O_RDWR;
    mode_t open_mode = S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH;
    char filename[80];
    int fd;

    if ( argc != 3 )
    {
        fprintf(stderr, "Usage: %s <domain_id> <num_pages>\n", argv[0]);
        return -1;
    }

    domain_id = atoi(argv[1]);
    num_pages = atoi(argv[2]);

    victims = calloc(num_pages, sizeof(xenpaging_victim_t));

    /* Open file */
    sprintf(filename, "page_cache_%d", domain_id);
    fd = open(filename, open_flags, open_mode);
    if ( fd < 0 )
    {
        perror("failed to open file");
        return -1;
    }

    /* Seed random-number generator */
    srand(time(NULL));

    /* Initialise domain paging */
    paging = xenpaging_init(&xch, domain_id);
    if ( paging == NULL )
    {
        ERROR("Error initialising paging");
        goto out;
    }

    /* Evict pages */
    memset(victims, 0, sizeof(xenpaging_victim_t) * num_pages);
    for ( i = 0; i < num_pages; i++ )
    {
        evict_victim(xch, paging, domain_id, &victims[i], fd, i);
        if ( i % 100 == 0 )
            DPRINTF("%d pages evicted\n", i);
    }

    DPRINTF("pages evicted\n");

    /* Swap pages in and out */
    while ( 1 )
    {
        /* Wait for Xen to signal that a page needs paged in */
        rc = xc_wait_for_event_or_timeout(xch, paging->mem_event.xce_handle, 100);
        if ( rc < -1 )
        {
            ERROR("Error getting event");
            goto out;
        }
        else if ( rc != -1 )
        {
            DPRINTF("Got event from Xen\n");
        }

        while ( RING_HAS_UNCONSUMED_REQUESTS(&paging->mem_event.back_ring) )
        {
            rc = get_request(&paging->mem_event, &req);
            if ( rc != 0 )
            {
                ERROR("Error getting request");
                goto out;
            }

            /* Check if the page has already been paged in */
            if ( test_and_clear_bit(req.gfn, paging->bitmap) )
            {
                /* Find where in the paging file to read from */
                for ( i = 0; i < num_pages; i++ )
                {
                    if ( (victims[i].domain_id == paging->mem_event.domain_id) &&
                         (victims[i].gfn == req.gfn) )
                        break;
                }
    
                if ( i >= num_pages )
                {
                    DPRINTF("Couldn't find page %"PRIx64"\n", req.gfn);
                    goto out;
                }
                
                /* Populate the page */
                rc = xenpaging_populate_page(xch, paging, &req.gfn, fd, i);
                if ( rc != 0 )
                {
                    ERROR("Error populating page");
                    goto out;
                }

                /* Prepare the response */
                rsp.gfn = req.gfn;
                rsp.p2mt = req.p2mt;
                rsp.vcpu_id = req.vcpu_id;
                rsp.flags = req.flags;

                rc = xenpaging_resume_page(paging, &rsp);
                if ( rc != 0 )
                {
                    ERROR("Error resuming page");
                    goto out;
                }

                /* Evict a new page to replace the one we just paged in */
                evict_victim(xch, paging, domain_id, &victims[i], fd, i);
            }
            else
            {
                DPRINTF("page already populated (domain = %d; vcpu = %d;"
                        " gfn = %"PRIx64"; paused = %"PRId64")\n",
                        paging->mem_event.domain_id, req.vcpu_id,
                        req.gfn, req.flags & MEM_EVENT_FLAG_VCPU_PAUSED);

                /* Tell Xen to resume the vcpu */
                /* XXX: Maybe just check if the vcpu was paused? */
                if ( req.flags & MEM_EVENT_FLAG_VCPU_PAUSED )
                {
                    /* Prepare the response */
                    rsp.gfn = req.gfn;
                    rsp.p2mt = req.p2mt;
                    rsp.vcpu_id = req.vcpu_id;
                    rsp.flags = req.flags;

                    rc = xenpaging_resume_page(paging, &rsp);
                    if ( rc != 0 )
                    {
                        ERROR("Error resuming");
                        goto out;
                    }
                }
            }
        }
    }

 out:
    free(victims);

    /* Tear down domain paging */
    rc1 = xenpaging_teardown(xch, paging);
    if ( rc1 != 0 )
        ERROR("Error tearing down paging");

    if ( rc == 0 )
        rc = rc1;

    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End: 
 */
