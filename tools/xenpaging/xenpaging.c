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

#define _XOPEN_SOURCE	600

#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <xc_private.h>
#include <xs.h>

#include "xc_bitops.h"
#include "file_ops.h"
#include "policy.h"
#include "xenpaging.h"

static char watch_token[16];
static char filename[80];
static int interrupted;

static void unlink_pagefile(void)
{
    if ( filename[0] )
    {
        unlink(filename);
        filename[0] = '\0';
    }
}

static void close_handler(int sig)
{
    interrupted = sig;
    unlink_pagefile();
}

static int xenpaging_mem_paging_flush_ioemu_cache(xenpaging_t *paging)
{
    struct xs_handle *xsh = paging->xs_handle;
    domid_t domain_id = paging->mem_event.domain_id;
    char path[80];
    bool rc;

    sprintf(path, "/local/domain/0/device-model/%u/command", domain_id);

    rc = xs_write(xsh, XBT_NULL, path, "flush-cache", strlen("flush-cache")); 

    return rc == true ? 0 : -1;
}

static int xenpaging_wait_for_event_or_timeout(xenpaging_t *paging)
{
    xc_interface *xch = paging->xc_handle;
    xc_evtchn *xce = paging->mem_event.xce_handle;
    char **vec;
    unsigned int num;
    struct pollfd fd[2];
    int port;
    int rc;

    /* Wait for event channel and xenstore */
    fd[0].fd = xc_evtchn_fd(xce);
    fd[0].events = POLLIN | POLLERR;
    fd[1].fd = xs_fileno(paging->xs_handle);
    fd[1].events = POLLIN | POLLERR;

    rc = poll(fd, 2, 100);
    if ( rc < 0 )
    {
        if (errno == EINTR)
            return 0;

        ERROR("Poll exited with an error");
        return -errno;
    }

    /* First check for guest shutdown */
    if ( rc && fd[1].revents & POLLIN )
    {
        DPRINTF("Got event from xenstore\n");
        vec = xs_read_watch(paging->xs_handle, &num);
        if ( vec )
        {
            if ( strcmp(vec[XS_WATCH_TOKEN], watch_token) == 0 )
            {
                /* If our guest disappeared, set interrupt flag and fall through */
                if ( xs_is_domain_introduced(paging->xs_handle, paging->mem_event.domain_id) == false )
                {
                    xs_unwatch(paging->xs_handle, "@releaseDomain", watch_token);
                    interrupted = SIGQUIT;
                    rc = 0;
                }
            }
            free(vec);
        }
    }

    if ( rc && fd[0].revents & POLLIN )
    {
        DPRINTF("Got event from evtchn\n");
        port = xc_evtchn_pending(xce);
        if ( port == -1 )
        {
            ERROR("Failed to read port from event channel");
            rc = -1;
            goto err;
        }

        rc = xc_evtchn_unmask(xce, port);
        if ( rc < 0 )
        {
            ERROR("Failed to unmask event channel port");
        }
    }
err:
    return rc;
}

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

static xenpaging_t *xenpaging_init(domid_t domain_id, int num_pages)
{
    xenpaging_t *paging;
    xc_interface *xch;
    xentoollog_logger *dbg = NULL;
    char *p;
    int rc;

    if ( getenv("XENPAGING_DEBUG") )
        dbg = (xentoollog_logger *)xtl_createlogger_stdiostream(stderr, XTL_DEBUG, 0);
    xch = xc_interface_open(dbg, NULL, 0);
    if ( !xch )
        goto err_iface;

    DPRINTF("xenpaging init\n");

    /* Allocate memory */
    paging = malloc(sizeof(xenpaging_t));
    memset(paging, 0, sizeof(xenpaging_t));

    /* Open connection to xenstore */
    paging->xs_handle = xs_open(0);
    if ( paging->xs_handle == NULL )
    {
        ERROR("Error initialising xenstore connection");
        goto err;
    }

    /* write domain ID to watch so we can ignore other domain shutdowns */
    snprintf(watch_token, sizeof(watch_token), "%u", domain_id);
    if ( xs_watch(paging->xs_handle, "@releaseDomain", watch_token) == false )
    {
        ERROR("Could not bind to shutdown watch\n");
        goto err;
    }

    p = getenv("XENPAGING_POLICY_MRU_SIZE");
    if ( p && *p )
    {
         paging->policy_mru_size = atoi(p);
         DPRINTF("Setting policy mru_size to %d\n", paging->policy_mru_size);
    }

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
        ERROR("Error initialising ring page");
        goto err;
    }

    /* Initialise ring */
    SHARED_RING_INIT((mem_event_sring_t *)paging->mem_event.ring_page);
    BACK_RING_INIT(&paging->mem_event.back_ring,
                   (mem_event_sring_t *)paging->mem_event.ring_page,
                   PAGE_SIZE);
    
    /* Initialise Xen */
    rc = xc_mem_event_enable(xch, paging->mem_event.domain_id,
                             paging->mem_event.shared_page,
                             paging->mem_event.ring_page);
    if ( rc != 0 )
    {
        switch ( errno ) {
            case EBUSY:
                ERROR("xenpaging is (or was) active on this domain");
                break;
            case ENODEV:
                ERROR("EPT not supported for this guest");
                break;
            default:
                ERROR("Error initialising shared page: %s", strerror(errno));
                break;
        }
        goto err;
    }

    /* Open event channel */
    paging->mem_event.xce_handle = xc_evtchn_open(NULL, 0);
    if ( paging->mem_event.xce_handle == NULL )
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

    /* Get domaininfo */
    paging->domain_info = malloc(sizeof(xc_domaininfo_t));
    if ( paging->domain_info == NULL )
    {
        ERROR("Error allocating memory for domain info");
        goto err;
    }

    rc = xc_domain_getinfolist(xch, paging->mem_event.domain_id, 1,
                               paging->domain_info);
    if ( rc != 1 )
    {
        ERROR("Error getting domain info");
        goto err;
    }

    /* Allocate bitmap for tracking pages that have been paged out */
    paging->bitmap = bitmap_alloc(paging->domain_info->max_pages);
    if ( !paging->bitmap )
    {
        ERROR("Error allocating bitmap");
        goto err;
    }
    DPRINTF("max_pages = %"PRIx64"\n", paging->domain_info->max_pages);

    if ( num_pages < 0 || num_pages > paging->domain_info->max_pages )
    {
        num_pages = paging->domain_info->max_pages;
        DPRINTF("setting num_pages to %d\n", num_pages);
    }
    paging->num_pages = num_pages;

    /* Initialise policy */
    rc = policy_init(paging);
    if ( rc != 0 )
    {
        ERROR("Error initialising policy");
        goto err;
    }

    return paging;

 err:
    if ( paging )
    {
        if ( paging->xs_handle )
            xs_close(paging->xs_handle);
        xc_interface_close(xch);
        if ( paging->mem_event.shared_page )
        {
            munlock(paging->mem_event.shared_page, PAGE_SIZE);
            free(paging->mem_event.shared_page);
        }

        if ( paging->mem_event.ring_page )
        {
            munlock(paging->mem_event.ring_page, PAGE_SIZE);
            free(paging->mem_event.ring_page);
        }

        free(paging->bitmap);
        free(paging->domain_info);
        free(paging);
    }

 err_iface: 
    return NULL;
}

static int xenpaging_teardown(xenpaging_t *paging)
{
    int rc;
    xc_interface *xch;

    if ( paging == NULL )
        return 0;

    xch = paging->xc_handle;
    paging->xc_handle = NULL;
    /* Tear down domain paging in Xen */
    rc = xc_mem_event_disable(xch, paging->mem_event.domain_id);
    if ( rc != 0 )
    {
        ERROR("Error tearing down domain paging in xen");
    }

    /* Unbind VIRQ */
    rc = xc_evtchn_unbind(paging->mem_event.xce_handle, paging->mem_event.port);
    if ( rc != 0 )
    {
        ERROR("Error unbinding event port");
    }
    paging->mem_event.port = -1;

    /* Close event channel */
    rc = xc_evtchn_close(paging->mem_event.xce_handle);
    if ( rc != 0 )
    {
        ERROR("Error closing event channel");
    }
    paging->mem_event.xce_handle = NULL;
    
    /* Close connection to xenstore */
    xs_close(paging->xs_handle);

    /* Close connection to Xen */
    rc = xc_interface_close(xch);
    if ( rc != 0 )
    {
        ERROR("Error closing connection to xen");
    }

    return 0;

 err:
    return -1;
}

static void get_request(mem_event_t *mem_event, mem_event_request_t *req)
{
    mem_event_back_ring_t *back_ring;
    RING_IDX req_cons;

    back_ring = &mem_event->back_ring;
    req_cons = back_ring->req_cons;

    /* Copy request */
    memcpy(req, RING_GET_REQUEST(back_ring, req_cons), sizeof(*req));
    req_cons++;

    /* Update ring */
    back_ring->req_cons = req_cons;
    back_ring->sring->req_event = req_cons + 1;
}

static void put_response(mem_event_t *mem_event, mem_event_response_t *rsp)
{
    mem_event_back_ring_t *back_ring;
    RING_IDX rsp_prod;

    back_ring = &mem_event->back_ring;
    rsp_prod = back_ring->rsp_prod_pvt;

    /* Copy response */
    memcpy(RING_GET_RESPONSE(back_ring, rsp_prod), rsp, sizeof(*rsp));
    rsp_prod++;

    /* Update ring */
    back_ring->rsp_prod_pvt = rsp_prod;
    RING_PUSH_RESPONSES(back_ring);
}

static int xenpaging_evict_page(xenpaging_t *paging,
                         xenpaging_victim_t *victim, int fd, int i)
{
    xc_interface *xch = paging->xc_handle;
    void *page;
    unsigned long gfn;
    int ret;

    DECLARE_DOMCTL;

    /* Map page */
    gfn = victim->gfn;
    ret = -EFAULT;
    page = xc_map_foreign_pages(xch, paging->mem_event.domain_id,
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
    ret = xc_mem_paging_evict(xch, paging->mem_event.domain_id,
                              victim->gfn);
    if ( ret != 0 )
    {
        ERROR("Error evicting page");
        goto out;
    }

    DPRINTF("evict_page > gfn %lx pageslot %d\n", victim->gfn, i);
    /* Notify policy of page being paged out */
    policy_notify_paged_out(victim->gfn);

 out:
    return ret;
}

static int xenpaging_resume_page(xenpaging_t *paging, mem_event_response_t *rsp, int notify_policy)
{
    int ret;

    /* Put the page info on the ring */
    put_response(&paging->mem_event, rsp);

    /* Notify policy of page being paged in */
    if ( notify_policy )
        policy_notify_paged_in(rsp->gfn);

    /* Tell Xen page is ready */
    ret = xc_mem_paging_resume(paging->xc_handle, paging->mem_event.domain_id,
                               rsp->gfn);
    if ( ret == 0 ) 
        ret = xc_evtchn_notify(paging->mem_event.xce_handle,
                               paging->mem_event.port);

 out:
    return ret;
}

static int xenpaging_populate_page(xenpaging_t *paging,
    xen_pfn_t gfn, int fd, int i)
{
    xc_interface *xch = paging->xc_handle;
    void *page;
    int ret;
    unsigned char oom = 0;

    DPRINTF("populate_page < gfn %"PRI_xen_pfn" pageslot %d\n", gfn, i);
    do
    {
        /* Tell Xen to allocate a page for the domain */
        ret = xc_mem_paging_prep(xch, paging->mem_event.domain_id, gfn);
        if ( ret != 0 )
        {
            if ( errno == ENOMEM )
            {
                if ( oom++ == 0 )
                    DPRINTF("ENOMEM while preparing gfn %"PRI_xen_pfn"\n", gfn);
                sleep(1);
                continue;
            }
            ERROR("Error preparing for page in");
            goto out_map;
        }
    }
    while ( ret && !interrupted );

    /* Map page */
    ret = -EFAULT;
    page = xc_map_foreign_pages(xch, paging->mem_event.domain_id,
                                PROT_READ | PROT_WRITE, &gfn, 1);
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

static int evict_victim(xenpaging_t *paging,
                        xenpaging_victim_t *victim, int fd, int i)
{
    xc_interface *xch = paging->xc_handle;
    int j = 0;
    int ret;

    do
    {
        ret = policy_choose_victim(paging, victim);
        if ( ret != 0 )
        {
            if ( ret != -ENOSPC )
                ERROR("Error choosing victim");
            goto out;
        }

        if ( interrupted )
        {
            ret = -EINTR;
            goto out;
        }
        ret = xc_mem_paging_nominate(xch, paging->mem_event.domain_id, victim->gfn);
        if ( ret == 0 )
            ret = xenpaging_evict_page(paging, victim, fd, i);
        else
        {
            if ( j++ % 1000 == 0 )
                if ( xenpaging_mem_paging_flush_ioemu_cache(paging) )
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
    struct sigaction act;
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
    int fd;

    if ( argc != 3 )
    {
        fprintf(stderr, "Usage: %s <domain_id> <num_pages>\n", argv[0]);
        return -1;
    }

    /* Initialise domain paging */
    paging = xenpaging_init(atoi(argv[1]), atoi(argv[2]));
    if ( paging == NULL )
    {
        fprintf(stderr, "Error initialising paging");
        return 1;
    }
    xch = paging->xc_handle;

    DPRINTF("starting %s %u %d\n", argv[0], paging->mem_event.domain_id, paging->num_pages);

    /* Open file */
    sprintf(filename, "page_cache_%u", paging->mem_event.domain_id);
    fd = open(filename, open_flags, open_mode);
    if ( fd < 0 )
    {
        perror("failed to open file");
        return 2;
    }

    victims = calloc(paging->num_pages, sizeof(xenpaging_victim_t));

    /* ensure that if we get a signal, we'll do cleanup, then exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* listen for page-in events to stop pager */
    create_page_in_thread(paging);

    /* Evict pages */
    for ( i = 0; i < paging->num_pages; i++ )
    {
        rc = evict_victim(paging, &victims[i], fd, i);
        if ( rc == -ENOSPC )
            break;
        if ( rc == -EINTR )
            break;
        if ( i % 100 == 0 )
            DPRINTF("%d pages evicted\n", i);
    }

    DPRINTF("%d pages evicted. Done.\n", i);

    /* Swap pages in and out */
    while ( 1 )
    {
        /* Wait for Xen to signal that a page needs paged in */
        rc = xenpaging_wait_for_event_or_timeout(paging);
        if ( rc < 0 )
        {
            ERROR("Error getting event");
            goto out;
        }
        else if ( rc != 0 )
        {
            DPRINTF("Got event from Xen\n");
        }

        while ( RING_HAS_UNCONSUMED_REQUESTS(&paging->mem_event.back_ring) )
        {
            get_request(&paging->mem_event, &req);

            /* Check if the page has already been paged in */
            if ( test_and_clear_bit(req.gfn, paging->bitmap) )
            {
                /* Find where in the paging file to read from */
                for ( i = 0; i < paging->num_pages; i++ )
                {
                    if ( victims[i].gfn == req.gfn )
                        break;
                }
    
                if ( i >= paging->num_pages )
                {
                    DPRINTF("Couldn't find page %"PRIx64"\n", req.gfn);
                    goto out;
                }
                
                if ( req.flags & MEM_EVENT_FLAG_DROP_PAGE )
                {
                    DPRINTF("drop_page ^ gfn %"PRIx64" pageslot %d\n", req.gfn, i);
                    /* Notify policy of page being dropped */
                    policy_notify_paged_in(req.gfn);
                }
                else
                {
                    /* Populate the page */
                    rc = xenpaging_populate_page(paging, req.gfn, fd, i);
                    if ( rc != 0 )
                    {
                        ERROR("Error populating page");
                        goto out;
                    }
                }

                /* Prepare the response */
                rsp.gfn = req.gfn;
                rsp.vcpu_id = req.vcpu_id;
                rsp.flags = req.flags;

                rc = xenpaging_resume_page(paging, &rsp, 1);
                if ( rc != 0 )
                {
                    ERROR("Error resuming page");
                    goto out;
                }

                /* Evict a new page to replace the one we just paged in,
                 * or clear this pagefile slot on exit */
                if ( interrupted )
                    victims[i].gfn = INVALID_MFN;
                else
                    evict_victim(paging, &victims[i], fd, i);
            }
            else
            {
                DPRINTF("page already populated (domain = %d; vcpu = %d;"
                        " gfn = %"PRIx64"; paused = %d)\n",
                        paging->mem_event.domain_id, req.vcpu_id,
                        req.gfn, req.flags & MEM_EVENT_FLAG_VCPU_PAUSED);

                /* Tell Xen to resume the vcpu */
                /* XXX: Maybe just check if the vcpu was paused? */
                if ( req.flags & MEM_EVENT_FLAG_VCPU_PAUSED )
                {
                    /* Prepare the response */
                    rsp.gfn = req.gfn;
                    rsp.vcpu_id = req.vcpu_id;
                    rsp.flags = req.flags;

                    rc = xenpaging_resume_page(paging, &rsp, 0);
                    if ( rc != 0 )
                    {
                        ERROR("Error resuming");
                        goto out;
                    }
                }
            }
        }

        /* Write all pages back into the guest */
        if ( interrupted == SIGTERM || interrupted == SIGINT )
        {
            int num = 0;
            for ( i = 0; i < paging->domain_info->max_pages; i++ )
            {
                if ( test_bit(i, paging->bitmap) )
                {
                    paging->pagein_queue[num] = i;
                    num++;
                    if ( num == XENPAGING_PAGEIN_QUEUE_SIZE )
                        break;
                }
            }
            /*
             * One more round if there are still pages to process.
             * If no more pages to process, exit loop.
             */
            if ( num )
                page_in_trigger();
            else if ( i == paging->domain_info->max_pages )
                break;
        }
        else
        {
            /* Exit on any other signal */
            if ( interrupted )
                break;
        }
    }
    DPRINTF("xenpaging got signal %d\n", interrupted);

 out:
    close(fd);
    unlink_pagefile();
    free(victims);

    /* Tear down domain paging */
    rc1 = xenpaging_teardown(paging);
    if ( rc1 != 0 )
        fprintf(stderr, "Error tearing down paging");

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
