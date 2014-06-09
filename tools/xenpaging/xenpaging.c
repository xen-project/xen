/******************************************************************************
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

#define _GNU_SOURCE

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <xc_private.h>
#include <xenstore.h>
#include <getopt.h>

#include "xc_bitops.h"
#include "file_ops.h"
#include "policy.h"
#include "xenpaging.h"

/* Defines number of mfns a guest should use at a time, in KiB */
#define WATCH_TARGETPAGES "memory/target-tot_pages"
static char *watch_target_tot_pages;
static char *dom_path;
static char watch_token[16];
static char *filename;
static int interrupted;

static void unlink_pagefile(void)
{
    if ( filename && filename[0] )
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

static void xenpaging_mem_paging_flush_ioemu_cache(struct xenpaging *paging)
{
    struct xs_handle *xsh = paging->xs_handle;
    domid_t domain_id = paging->mem_event.domain_id;
    char path[80];

    sprintf(path, "/local/domain/0/device-model/%u/command", domain_id);

    xs_write(xsh, XBT_NULL, path, "flush-cache", strlen("flush-cache")); 
}

static int xenpaging_wait_for_event_or_timeout(struct xenpaging *paging)
{
    xc_interface *xch = paging->xc_handle;
    xc_evtchn *xce = paging->mem_event.xce_handle;
    char **vec, *val;
    unsigned int num;
    struct pollfd fd[2];
    int port;
    int rc;
    int timeout;

    /* Wait for event channel and xenstore */
    fd[0].fd = xc_evtchn_fd(xce);
    fd[0].events = POLLIN | POLLERR;
    fd[1].fd = xs_fileno(paging->xs_handle);
    fd[1].events = POLLIN | POLLERR;

    /* No timeout while page-out is still in progress */
    timeout = paging->use_poll_timeout ? 100 : 0;
    rc = poll(fd, 2, timeout);
    if ( rc < 0 )
    {
        if (errno == EINTR)
            return 0;

        PERROR("Poll exited with an error");
        return -1;
    }

    /* First check for guest shutdown */
    if ( rc && fd[1].revents & POLLIN )
    {
        DPRINTF("Got event from xenstore\n");
        vec = xs_read_watch(paging->xs_handle, &num);
        if ( vec )
        {
            DPRINTF("path '%s' token '%s'\n", vec[XS_WATCH_PATH], vec[XS_WATCH_TOKEN]);
            if ( strcmp(vec[XS_WATCH_TOKEN], watch_token) == 0 )
            {
                /* If our guest disappeared, set interrupt flag and fall through */
                if ( xs_is_domain_introduced(paging->xs_handle, paging->mem_event.domain_id) == false )
                {
                    xs_unwatch(paging->xs_handle, "@releaseDomain", watch_token);
                    interrupted = SIGQUIT;
                    /* No further poll result processing */
                    rc = 0;
                }
            }
            else if ( strcmp(vec[XS_WATCH_PATH], watch_target_tot_pages) == 0 )
            {
                int ret, target_tot_pages;
                val = xs_read(paging->xs_handle, XBT_NULL, vec[XS_WATCH_PATH], NULL);
                if ( val )
                {
                    ret = sscanf(val, "%d", &target_tot_pages);
                    if ( ret > 0 )
                    {
                        /* KiB to pages */
                        target_tot_pages >>= 2;
                        if ( target_tot_pages < 0 || target_tot_pages > paging->max_pages )
                            target_tot_pages = paging->max_pages;
                        paging->target_tot_pages = target_tot_pages;
                        /* Disable poll() delay while new target is not yet reached */
                        paging->use_poll_timeout = 0;
                        DPRINTF("new target_tot_pages %d\n", target_tot_pages);
                    }
                    free(val);
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
            PERROR("Failed to read port from event channel");
            rc = -1;
            goto err;
        }

        rc = xc_evtchn_unmask(xce, port);
        if ( rc < 0 )
        {
            PERROR("Failed to unmask event channel port");
        }
    }
err:
    return rc;
}

static int xenpaging_get_tot_pages(struct xenpaging *paging)
{
    xc_interface *xch = paging->xc_handle;
    xc_domaininfo_t domain_info;
    int rc;

    rc = xc_domain_getinfolist(xch, paging->mem_event.domain_id, 1, &domain_info);
    if ( rc != 1 )
    {
        PERROR("Error getting domain info");
        return -1;
    }
    return domain_info.tot_pages;
}

static void *init_page(void)
{
    void *buffer;

    /* Allocated page memory */
    errno = posix_memalign(&buffer, PAGE_SIZE, PAGE_SIZE);
    if ( errno != 0 )
        return NULL;

    /* Lock buffer in memory so it can't be paged out */
    if ( mlock(buffer, PAGE_SIZE) < 0 )
    {
        free(buffer);
        buffer = NULL;
    }

    return buffer;
}

static void usage(void)
{
    printf("usage:\n\n");

    printf("  xenpaging [options] -f <pagefile> -d <domain_id>\n\n");

    printf("options:\n");
    printf(" -d <domid>     --domain=<domid>         numerical domain_id of guest. This option is required.\n");
    printf(" -f <file>      --pagefile=<file>        pagefile to use. This option is required.\n");
    printf(" -m <max_memkb> --max_memkb=<max_memkb>  maximum amount of memory to handle.\n");
    printf(" -r <num>       --mru_size=<num>         number of paged-in pages to keep in memory.\n");
    printf(" -v             --verbose                enable debug output.\n");
    printf(" -h             --help                   this output.\n");
}

static int xenpaging_getopts(struct xenpaging *paging, int argc, char *argv[])
{
    int ch;
    static const char sopts[] = "hvd:f:m:r:";
    static const struct option lopts[] = {
        {"help", 0, NULL, 'h'},
        {"verbose", 0, NULL, 'v'},
        {"domain", 1, NULL, 'd'},
        {"pagefile", 1, NULL, 'f'},
        {"mru_size", 1, NULL, 'm'},
        { }
    };

    while ((ch = getopt_long(argc, argv, sopts, lopts, NULL)) != -1)
    {
        switch(ch) {
        case 'd':
            paging->mem_event.domain_id = atoi(optarg);
            break;
        case 'f':
            filename = strdup(optarg);
            break;
        case 'm':
            /* KiB to pages */
            paging->max_pages = atoi(optarg) >> 2;
            break;
        case 'r':
            paging->policy_mru_size = atoi(optarg);
            break;
        case 'v':
            paging->debug = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 1;
        }
    }

    argv += optind; argc -= optind;
    
    /* Path to pagefile is required */
    if ( !filename )
    {
        printf("Filename for pagefile missing!\n");
        usage();
        return 1;
    }

    /* Set domain id */
    if ( !paging->mem_event.domain_id )
    {
        printf("Numerical <domain_id> missing!\n");
        return 1;
    }

    return 0;
}

static struct xenpaging *xenpaging_init(int argc, char *argv[])
{
    struct xenpaging *paging;
    xc_domaininfo_t domain_info;
    xc_interface *xch = NULL;
    xentoollog_logger *dbg = NULL;
    char *p;
    int rc;
    unsigned long ring_pfn, mmap_pfn;

    /* Allocate memory */
    paging = calloc(1, sizeof(struct xenpaging));
    if ( !paging )
        goto err;

    /* Get cmdline options and domain_id */
    if ( xenpaging_getopts(paging, argc, argv) )
        goto err;

    /* Enable debug output */
    if ( paging->debug )
        dbg = (xentoollog_logger *)xtl_createlogger_stdiostream(stderr, XTL_DEBUG, 0);

    /* Open connection to xen */
    paging->xc_handle = xch = xc_interface_open(dbg, NULL, 0);
    if ( !xch )
        goto err;

    DPRINTF("xenpaging init\n");

    /* Open connection to xenstore */
    paging->xs_handle = xs_open(0);
    if ( paging->xs_handle == NULL )
    {
        PERROR("Error initialising xenstore connection");
        goto err;
    }

    /* write domain ID to watch so we can ignore other domain shutdowns */
    snprintf(watch_token, sizeof(watch_token), "%u", paging->mem_event.domain_id);
    if ( xs_watch(paging->xs_handle, "@releaseDomain", watch_token) == false )
    {
        PERROR("Could not bind to shutdown watch\n");
        goto err;
    }

    /* Watch xenpagings working target */
    dom_path = xs_get_domain_path(paging->xs_handle, paging->mem_event.domain_id);
    if ( !dom_path )
    {
        PERROR("Could not find domain path\n");
        goto err;
    }
    if ( asprintf(&watch_target_tot_pages, "%s/%s", dom_path, WATCH_TARGETPAGES) < 0 )
    {
        PERROR("Could not alloc watch path\n");
        goto err;
    }
    DPRINTF("watching '%s'\n", watch_target_tot_pages);
    if ( xs_watch(paging->xs_handle, watch_target_tot_pages, "") == false )
    {
        PERROR("Could not bind to xenpaging watch\n");
        goto err;
    }

    /* Map the ring page */
    xc_get_hvm_param(xch, paging->mem_event.domain_id, 
                        HVM_PARAM_PAGING_RING_PFN, &ring_pfn);
    mmap_pfn = ring_pfn;
    paging->mem_event.ring_page = 
        xc_map_foreign_batch(xch, paging->mem_event.domain_id, 
                                PROT_READ | PROT_WRITE, &mmap_pfn, 1);
    if ( mmap_pfn & XEN_DOMCTL_PFINFO_XTAB )
    {
        /* Map failed, populate ring page */
        rc = xc_domain_populate_physmap_exact(paging->xc_handle, 
                                              paging->mem_event.domain_id,
                                              1, 0, 0, &ring_pfn);
        if ( rc != 0 )
        {
            PERROR("Failed to populate ring gfn\n");
            goto err;
        }

        mmap_pfn = ring_pfn;
        paging->mem_event.ring_page = 
            xc_map_foreign_batch(xch, paging->mem_event.domain_id, 
                                    PROT_READ | PROT_WRITE, &mmap_pfn, 1);
        if ( mmap_pfn & XEN_DOMCTL_PFINFO_XTAB )
        {
            PERROR("Could not map the ring page\n");
            goto err;
        }
    }
    
    /* Initialise Xen */
    rc = xc_mem_paging_enable(xch, paging->mem_event.domain_id,
                             &paging->mem_event.evtchn_port);
    if ( rc != 0 )
    {
        switch ( errno ) {
            case EBUSY:
                ERROR("xenpaging is (or was) active on this domain");
                break;
            case ENODEV:
                ERROR("xenpaging requires Hardware Assisted Paging");
                break;
            case EMLINK:
                ERROR("xenpaging not supported while iommu passthrough is enabled");
                break;
            case EXDEV:
                ERROR("xenpaging not supported in a PoD guest");
                break;
            default:
                PERROR("Error initialising shared page");
                break;
        }
        goto err;
    }

    /* Open event channel */
    paging->mem_event.xce_handle = xc_evtchn_open(NULL, 0);
    if ( paging->mem_event.xce_handle == NULL )
    {
        PERROR("Failed to open event channel");
        goto err;
    }

    /* Bind event notification */
    rc = xc_evtchn_bind_interdomain(paging->mem_event.xce_handle,
                                    paging->mem_event.domain_id,
                                    paging->mem_event.evtchn_port);
    if ( rc < 0 )
    {
        PERROR("Failed to bind event channel");
        goto err;
    }

    paging->mem_event.port = rc;

    /* Initialise ring */
    SHARED_RING_INIT((mem_event_sring_t *)paging->mem_event.ring_page);
    BACK_RING_INIT(&paging->mem_event.back_ring,
                   (mem_event_sring_t *)paging->mem_event.ring_page,
                   PAGE_SIZE);

    /* Now that the ring is set, remove it from the guest's physmap */
    if ( xc_domain_decrease_reservation_exact(xch, 
                    paging->mem_event.domain_id, 1, 0, &ring_pfn) )
        PERROR("Failed to remove ring from guest physmap");

    /* Get max_pages from guest if not provided via cmdline */
    if ( !paging->max_pages )
    {
        rc = xc_domain_getinfolist(xch, paging->mem_event.domain_id, 1,
                                   &domain_info);
        if ( rc != 1 )
        {
            PERROR("Error getting domain info");
            goto err;
        }

        /* Record number of max_pages */
        paging->max_pages = domain_info.max_pages;
    }

    /* Allocate bitmap for tracking pages that have been paged out */
    paging->bitmap = bitmap_alloc(paging->max_pages);
    if ( !paging->bitmap )
    {
        PERROR("Error allocating bitmap");
        goto err;
    }
    DPRINTF("max_pages = %d\n", paging->max_pages);

    /* Allocate indicies for pagefile slots */
    paging->slot_to_gfn = calloc(paging->max_pages, sizeof(*paging->slot_to_gfn));
    paging->gfn_to_slot = calloc(paging->max_pages, sizeof(*paging->gfn_to_slot));
    if ( !paging->slot_to_gfn || !paging->gfn_to_slot )
        goto err;

    /* Allocate stack for known free slots in pagefile */
    paging->free_slot_stack = calloc(paging->max_pages, sizeof(*paging->free_slot_stack));
    if ( !paging->free_slot_stack )
        goto err;

    /* Initialise policy */
    rc = policy_init(paging);
    if ( rc != 0 )
    {
        PERROR("Error initialising policy");
        goto err;
    }

    paging->paging_buffer = init_page();
    if ( !paging->paging_buffer )
    {
        PERROR("Creating page aligned load buffer");
        goto err;
    }

    /* Open file */
    paging->fd = open(filename, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    if ( paging->fd < 0 )
    {
        PERROR("failed to open file");
        goto err;
    }

    return paging;

 err:
    if ( paging )
    {
        if ( paging->xs_handle )
            xs_close(paging->xs_handle);
        if ( xch )
            xc_interface_close(xch);
        if ( paging->paging_buffer )
        {
            munlock(paging->paging_buffer, PAGE_SIZE);
            free(paging->paging_buffer);
        }

        if ( paging->mem_event.ring_page )
        {
            munmap(paging->mem_event.ring_page, PAGE_SIZE);
        }

        free(dom_path);
        free(watch_target_tot_pages);
        free(paging->free_slot_stack);
        free(paging->slot_to_gfn);
        free(paging->gfn_to_slot);
        free(paging->bitmap);
        free(paging);
    }

    return NULL;
}

static void xenpaging_teardown(struct xenpaging *paging)
{
    int rc;
    xc_interface *xch = paging->xc_handle;

    xs_unwatch(paging->xs_handle, watch_target_tot_pages, "");
    xs_unwatch(paging->xs_handle, "@releaseDomain", watch_token);

    paging->xc_handle = NULL;
    /* Tear down domain paging in Xen */
    munmap(paging->mem_event.ring_page, PAGE_SIZE);
    rc = xc_mem_paging_disable(xch, paging->mem_event.domain_id);
    if ( rc != 0 )
    {
        PERROR("Error tearing down domain paging in xen");
    }

    /* Unbind VIRQ */
    rc = xc_evtchn_unbind(paging->mem_event.xce_handle, paging->mem_event.port);
    if ( rc != 0 )
    {
        PERROR("Error unbinding event port");
    }
    paging->mem_event.port = -1;

    /* Close event channel */
    rc = xc_evtchn_close(paging->mem_event.xce_handle);
    if ( rc != 0 )
    {
        PERROR("Error closing event channel");
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
}

static void get_request(struct mem_event *mem_event, mem_event_request_t *req)
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

static void put_response(struct mem_event *mem_event, mem_event_response_t *rsp)
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

/* Evict a given gfn
 * Returns < 0 on fatal error
 * Returns 0 on successful evict
 * Returns > 0 if gfn can not be evicted
 */
static int xenpaging_evict_page(struct xenpaging *paging, unsigned long gfn, int slot)
{
    xc_interface *xch = paging->xc_handle;
    void *page;
    xen_pfn_t victim = gfn;
    int ret;

    DECLARE_DOMCTL;

    /* Nominate page */
    ret = xc_mem_paging_nominate(xch, paging->mem_event.domain_id, gfn);
    if ( ret < 0 )
    {
        /* unpageable gfn is indicated by EBUSY */
        if ( errno == EBUSY )
            ret = 1;
        else
            PERROR("Error nominating page %lx", gfn);
        goto out;
    }

    /* Map page */
    page = xc_map_foreign_pages(xch, paging->mem_event.domain_id, PROT_READ, &victim, 1);
    if ( page == NULL )
    {
        PERROR("Error mapping page %lx", gfn);
        ret = -1;
        goto out;
    }

    /* Copy page */
    ret = write_page(paging->fd, page, slot);
    if ( ret < 0 )
    {
        PERROR("Error copying page %lx", gfn);
        munmap(page, PAGE_SIZE);
        ret = -1;
        goto out;
    }

    /* Release page */
    munmap(page, PAGE_SIZE);

    /* Tell Xen to evict page */
    ret = xc_mem_paging_evict(xch, paging->mem_event.domain_id, gfn);
    if ( ret < 0 )
    {
        /* A gfn in use is indicated by EBUSY */
        if ( errno == EBUSY )
        {
                ret = 1;
                DPRINTF("Nominated page %lx busy", gfn);
        } else
            PERROR("Error evicting page %lx", gfn);
        goto out;
    }

    DPRINTF("evict_page > gfn %lx pageslot %d\n", gfn, slot);
    /* Notify policy of page being paged out */
    policy_notify_paged_out(gfn);

    /* Update index */
    paging->slot_to_gfn[slot] = gfn;
    paging->gfn_to_slot[gfn] = slot;

    /* Record number of evicted pages */
    paging->num_paged_out++;

    ret = 0;

 out:
    return ret;
}

static int xenpaging_resume_page(struct xenpaging *paging, mem_event_response_t *rsp, int notify_policy)
{
    /* Put the page info on the ring */
    put_response(&paging->mem_event, rsp);

    /* Notify policy of page being paged in */
    if ( notify_policy )
    {
        /*
         * Do not add gfn to mru list if the target is lower than mru size.
         * This allows page-out of these gfns if the target grows again.
         */
        if (paging->num_paged_out > paging->policy_mru_size)
            policy_notify_paged_in(rsp->gfn);
        else
            policy_notify_paged_in_nomru(rsp->gfn);

       /* Record number of resumed pages */
       paging->num_paged_out--;
    }

    /* Tell Xen page is ready */
    return xc_evtchn_notify(paging->mem_event.xce_handle, paging->mem_event.port);
}

static int xenpaging_populate_page(struct xenpaging *paging, unsigned long gfn, int i)
{
    xc_interface *xch = paging->xc_handle;
    int ret;
    unsigned char oom = 0;

    DPRINTF("populate_page < gfn %lx pageslot %d\n", gfn, i);

    /* Read page */
    ret = read_page(paging->fd, paging->paging_buffer, i);
    if ( ret != 0 )
    {
        PERROR("Error reading page");
        goto out;
    }

    do
    {
        /* Tell Xen to allocate a page for the domain */
        ret = xc_mem_paging_load(xch, paging->mem_event.domain_id, gfn, paging->paging_buffer);
        if ( ret < 0 )
        {
            if ( errno == ENOMEM )
            {
                if ( oom++ == 0 )
                    DPRINTF("ENOMEM while preparing gfn %lx\n", gfn);
                sleep(1);
                continue;
            }
            PERROR("Error loading %lx during page-in", gfn);
            ret = -1;
            break;
        }
    }
    while ( ret && !interrupted );


 out:
    return ret;
}

/* Trigger a page-in for a batch of pages */
static void resume_pages(struct xenpaging *paging, int num_pages)
{
    xc_interface *xch = paging->xc_handle;
    int i, num = 0;

    for ( i = 0; i < paging->max_pages && num < num_pages; i++ )
    {
        if ( test_bit(i, paging->bitmap) )
        {
            paging->pagein_queue[num] = i;
            num++;
            if ( num == XENPAGING_PAGEIN_QUEUE_SIZE )
                break;
        }
    }
    /* num may be less than num_pages, caller has to try again */
    if ( num )
        page_in_trigger();
}

/* Evict one gfn and write it to the given slot
 * Returns < 0 on fatal error
 * Returns 0 on successful evict
 * Returns > 0 if no gfn can be evicted
 */
static int evict_victim(struct xenpaging *paging, int slot)
{
    xc_interface *xch = paging->xc_handle;
    unsigned long gfn;
    static int num_paged_out;
    int ret;

    do
    {
        gfn = policy_choose_victim(paging);
        if ( gfn == INVALID_MFN )
        {
            /* If the number did not change after last flush command then
             * the command did not reach qemu yet, or qemu still processes
             * the command, or qemu has nothing to release.
             * Right now there is no need to issue the command again.
             */
            if ( num_paged_out != paging->num_paged_out )
            {
                DPRINTF("Flushing qemu cache\n");
                xenpaging_mem_paging_flush_ioemu_cache(paging);
                num_paged_out = paging->num_paged_out;
            }
            ret = ENOSPC;
            goto out;
        }

        if ( interrupted )
        {
            ret = EINTR;
            goto out;
        }

        ret = xenpaging_evict_page(paging, gfn, slot);
        if ( ret < 0 )
            goto out;
    }
    while ( ret );

    if ( test_and_set_bit(gfn, paging->bitmap) )
        ERROR("Page %lx has been evicted before", gfn);

    ret = 0;

 out:
    return ret;
}

/* Evict a batch of pages and write them to a free slot in the paging file
 * Returns < 0 on fatal error
 * Returns 0 if no gfn can be evicted
 * Returns > 0 on successful evict
 */
static int evict_pages(struct xenpaging *paging, int num_pages)
{
    xc_interface *xch = paging->xc_handle;
    int rc, slot, num = 0;

    /* Reuse known free slots */
    while ( paging->stack_count > 0 && num < num_pages )
    {
        slot = paging->free_slot_stack[--paging->stack_count];
        rc = evict_victim(paging, slot);
        if ( rc )
        {
            num = rc < 0 ? -1 : num;
            return num;
        }
        num++;
    }

    /* Scan all slots slots for remainders */
    for ( slot = 0; slot < paging->max_pages && num < num_pages; slot++ )
    {
        /* Slot is allocated */
        if ( paging->slot_to_gfn[slot] )
            continue;

        rc = evict_victim(paging, slot);
        if ( rc )
        {
            num = rc < 0 ? -1 : num;
            break;
        }

        num++;
    }
    return num;
}

int main(int argc, char *argv[])
{
    struct sigaction act;
    struct xenpaging *paging;
    mem_event_request_t req;
    mem_event_response_t rsp;
    int num, prev_num = 0;
    int slot;
    int tot_pages;
    int rc;
    xc_interface *xch;

    /* Initialise domain paging */
    paging = xenpaging_init(argc, argv);
    if ( paging == NULL )
    {
        fprintf(stderr, "Error initialising paging\n");
        return 1;
    }
    xch = paging->xc_handle;

    DPRINTF("starting %s for domain_id %u with pagefile %s\n", argv[0], paging->mem_event.domain_id, filename);

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
            /* Indicate possible error */
            rc = 1;

            get_request(&paging->mem_event, &req);

            if ( req.gfn > paging->max_pages )
            {
                ERROR("Requested gfn %"PRIx64" higher than max_pages %x\n", req.gfn, paging->max_pages);
                goto out;
            }

            /* Check if the page has already been paged in */
            if ( test_and_clear_bit(req.gfn, paging->bitmap) )
            {
                /* Find where in the paging file to read from */
                slot = paging->gfn_to_slot[req.gfn];

                /* Sanity check */
                if ( paging->slot_to_gfn[slot] != req.gfn )
                {
                    ERROR("Expected gfn %"PRIx64" in slot %d, but found gfn %lx\n", req.gfn, slot, paging->slot_to_gfn[slot]);
                    goto out;
                }

                if ( req.flags & MEM_EVENT_FLAG_DROP_PAGE )
                {
                    DPRINTF("drop_page ^ gfn %"PRIx64" pageslot %d\n", req.gfn, slot);
                    /* Notify policy of page being dropped */
                    policy_notify_dropped(req.gfn);
                }
                else
                {
                    /* Populate the page */
                    if ( xenpaging_populate_page(paging, req.gfn, slot) < 0 )
                    {
                        ERROR("Error populating page %"PRIx64"", req.gfn);
                        goto out;
                    }
                }

                /* Prepare the response */
                rsp.gfn = req.gfn;
                rsp.vcpu_id = req.vcpu_id;
                rsp.flags = req.flags;

                if ( xenpaging_resume_page(paging, &rsp, 1) < 0 )
                {
                    PERROR("Error resuming page %"PRIx64"", req.gfn);
                    goto out;
                }

                /* Clear this pagefile slot */
                paging->slot_to_gfn[slot] = 0;

                /* Record this free slot */
                paging->free_slot_stack[paging->stack_count++] = slot;
            }
            else
            {
                DPRINTF("page %s populated (domain = %d; vcpu = %d;"
                        " gfn = %"PRIx64"; paused = %d; evict_fail = %d)\n",
                        req.flags & MEM_EVENT_FLAG_EVICT_FAIL ? "not" : "already",
                        paging->mem_event.domain_id, req.vcpu_id, req.gfn,
                        !!(req.flags & MEM_EVENT_FLAG_VCPU_PAUSED) ,
                        !!(req.flags & MEM_EVENT_FLAG_EVICT_FAIL) );

                /* Tell Xen to resume the vcpu */
                if (( req.flags & MEM_EVENT_FLAG_VCPU_PAUSED ) || ( req.flags & MEM_EVENT_FLAG_EVICT_FAIL ))
                {
                    /* Prepare the response */
                    rsp.gfn = req.gfn;
                    rsp.vcpu_id = req.vcpu_id;
                    rsp.flags = req.flags;

                    if ( xenpaging_resume_page(paging, &rsp, 0) < 0 )
                    {
                        PERROR("Error resuming page %"PRIx64"", req.gfn);
                        goto out;
                    }
                }
            }
        }

        /* If interrupted, write all pages back into the guest */
        if ( interrupted == SIGTERM || interrupted == SIGINT )
        {
            /* If no more pages to process, exit loop. */
            if ( !paging->num_paged_out )
                break;
            
            /* One more round if there are still pages to process. */
            resume_pages(paging, paging->num_paged_out);

            /* Resume main loop */
            continue;
        }

        /* Exit main loop on any other signal */
        if ( interrupted )
            break;

        /* Indicate possible error */
        rc = 1;

        /* Check if the target has been reached already */
        tot_pages = xenpaging_get_tot_pages(paging);
        if ( tot_pages < 0 )
            goto out;

        /* Resume all pages if paging is disabled or no target was set */
        if ( paging->target_tot_pages == 0 )
        {
            if ( paging->num_paged_out )
                resume_pages(paging, paging->num_paged_out);
        }
        /* Evict more pages if target not reached */
        else if ( tot_pages > paging->target_tot_pages )
        {
            num = tot_pages - paging->target_tot_pages;
            if ( num != prev_num )
            {
                DPRINTF("Need to evict %d pages to reach %d target_tot_pages\n", num, paging->target_tot_pages);
                prev_num = num;
            }
            /* Limit the number of evicts to be able to process page-in requests */
            if ( num > 42 )
            {
                paging->use_poll_timeout = 0;
                num = 42;
            }
            if ( evict_pages(paging, num) < 0 )
                goto out;
        }
        /* Resume some pages if target not reached */
        else if ( tot_pages < paging->target_tot_pages && paging->num_paged_out )
        {
            num = paging->target_tot_pages - tot_pages;
            if ( num != prev_num )
            {
                DPRINTF("Need to resume %d pages to reach %d target_tot_pages\n", num, paging->target_tot_pages);
                prev_num = num;
            }
            resume_pages(paging, num);
        }
        /* Now target was reached, enable poll() timeout */
        else
        {
            paging->use_poll_timeout = 1;
        }

    }

    /* No error */
    rc = 0;

    DPRINTF("xenpaging got signal %d\n", interrupted);

 out:
    close(paging->fd);
    unlink_pagefile();

    /* Tear down domain paging */
    xenpaging_teardown(paging);

    return rc ? 2 : 0;
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End: 
 */
