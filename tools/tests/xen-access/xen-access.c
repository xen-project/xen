/*
 * xen-access.c
 *
 * Exercises the basic per-page access mechanisms
 *
 * Copyright (c) 2011 Virtuata, Inc.
 * Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp), based on
 *   xenpaging.c
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/poll.h>

#include <xenctrl.h>
#include <xen/mem_event.h>

#define DPRINTF(a, b...) fprintf(stderr, a, ## b)
#define ERROR(a, b...) fprintf(stderr, a "\n", ## b)
#define PERROR(a, b...) fprintf(stderr, a ": %s\n", ## b, strerror(errno))

/* Spinlock and mem event definitions */

#define SPIN_LOCK_UNLOCKED 0

#define ADDR (*(volatile long *) addr)
/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline int test_and_set_bit(int nr, volatile void *addr)
{
    int oldbit;

    asm volatile (
        "btsl %2,%1\n\tsbbl %0,%0"
        : "=r" (oldbit), "=m" (ADDR)
        : "Ir" (nr), "m" (ADDR) : "memory");
    return oldbit;
}

typedef int spinlock_t;

static inline void spin_lock(spinlock_t *lock)
{
    while ( test_and_set_bit(1, lock) );
}

static inline void spin_lock_init(spinlock_t *lock)
{
    *lock = SPIN_LOCK_UNLOCKED;
}

static inline void spin_unlock(spinlock_t *lock)
{
    *lock = SPIN_LOCK_UNLOCKED;
}

static inline int spin_trylock(spinlock_t *lock)
{
    return !test_and_set_bit(1, lock);
}

#define mem_event_ring_lock_init(_m)  spin_lock_init(&(_m)->ring_lock)
#define mem_event_ring_lock(_m)       spin_lock(&(_m)->ring_lock)
#define mem_event_ring_unlock(_m)     spin_unlock(&(_m)->ring_lock)

typedef struct mem_event {
    domid_t domain_id;
    xc_evtchn *xce_handle;
    int port;
    mem_event_back_ring_t back_ring;
    uint32_t evtchn_port;
    void *ring_page;
    spinlock_t ring_lock;
} mem_event_t;

typedef struct xenaccess {
    xc_interface *xc_handle;

    xc_domaininfo_t    *domain_info;

    mem_event_t mem_event;
} xenaccess_t;

static int interrupted;
bool evtchn_bind = 0, evtchn_open = 0, mem_access_enable = 0;

static void close_handler(int sig)
{
    interrupted = sig;
}

int xc_wait_for_event_or_timeout(xc_interface *xch, xc_evtchn *xce, unsigned long ms)
{
    struct pollfd fd = { .fd = xc_evtchn_fd(xce), .events = POLLIN | POLLERR };
    int port;
    int rc;

    rc = poll(&fd, 1, ms);
    if ( rc == -1 )
    {
        if (errno == EINTR)
            return 0;

        ERROR("Poll exited with an error");
        goto err;
    }

    if ( rc == 1 )
    {
        port = xc_evtchn_pending(xce);
        if ( port == -1 )
        {
            ERROR("Failed to read port from event channel");
            goto err;
        }

        rc = xc_evtchn_unmask(xce, port);
        if ( rc != 0 )
        {
            ERROR("Failed to unmask event channel port");
            goto err;
        }
    }
    else
        port = -1;

    return port;

 err:
    return -errno;
}

int xenaccess_teardown(xc_interface *xch, xenaccess_t *xenaccess)
{
    int rc;

    if ( xenaccess == NULL )
        return 0;

    /* Tear down domain xenaccess in Xen */
    if ( xenaccess->mem_event.ring_page )
        munmap(xenaccess->mem_event.ring_page, XC_PAGE_SIZE);

    if ( mem_access_enable )
    {
        rc = xc_mem_access_disable(xenaccess->xc_handle,
                                   xenaccess->mem_event.domain_id);
        if ( rc != 0 )
        {
            ERROR("Error tearing down domain xenaccess in xen");
        }
    }

    /* Unbind VIRQ */
    if ( evtchn_bind )
    {
        rc = xc_evtchn_unbind(xenaccess->mem_event.xce_handle,
                              xenaccess->mem_event.port);
        if ( rc != 0 )
        {
            ERROR("Error unbinding event port");
        }
    }

    /* Close event channel */
    if ( evtchn_open )
    {
        rc = xc_evtchn_close(xenaccess->mem_event.xce_handle);
        if ( rc != 0 )
        {
            ERROR("Error closing event channel");
        }
    }

    /* Close connection to Xen */
    rc = xc_interface_close(xenaccess->xc_handle);
    if ( rc != 0 )
    {
        ERROR("Error closing connection to xen");
    }
    xenaccess->xc_handle = NULL;

    free(xenaccess->domain_info);
    free(xenaccess);

    return 0;
}

xenaccess_t *xenaccess_init(xc_interface **xch_r, domid_t domain_id)
{
    xenaccess_t *xenaccess = 0;
    xc_interface *xch;
    int rc;

    xch = xc_interface_open(NULL, NULL, 0);
    if ( !xch )
        goto err_iface;

    DPRINTF("xenaccess init\n");
    *xch_r = xch;

    /* Allocate memory */
    xenaccess = malloc(sizeof(xenaccess_t));
    memset(xenaccess, 0, sizeof(xenaccess_t));

    /* Open connection to xen */
    xenaccess->xc_handle = xch;

    /* Set domain id */
    xenaccess->mem_event.domain_id = domain_id;

    /* Initialise lock */
    mem_event_ring_lock_init(&xenaccess->mem_event);

    /* Enable mem_access */
    xenaccess->mem_event.ring_page =
            xc_mem_access_enable(xenaccess->xc_handle,
                                 xenaccess->mem_event.domain_id,
                                 &xenaccess->mem_event.evtchn_port);
    if ( xenaccess->mem_event.ring_page == NULL )
    {
        switch ( errno ) {
            case EBUSY:
                ERROR("xenaccess is (or was) active on this domain");
                break;
            case ENODEV:
                ERROR("EPT not supported for this guest");
                break;
            default:
                perror("Error enabling mem_access");
                break;
        }
        goto err;
    }
    mem_access_enable = 1;

    /* Open event channel */
    xenaccess->mem_event.xce_handle = xc_evtchn_open(NULL, 0);
    if ( xenaccess->mem_event.xce_handle == NULL )
    {
        ERROR("Failed to open event channel");
        goto err;
    }
    evtchn_open = 1;

    /* Bind event notification */
    rc = xc_evtchn_bind_interdomain(xenaccess->mem_event.xce_handle,
                                    xenaccess->mem_event.domain_id,
                                    xenaccess->mem_event.evtchn_port);
    if ( rc < 0 )
    {
        ERROR("Failed to bind event channel");
        goto err;
    }
    evtchn_bind = 1;
    xenaccess->mem_event.port = rc;

    /* Initialise ring */
    SHARED_RING_INIT((mem_event_sring_t *)xenaccess->mem_event.ring_page);
    BACK_RING_INIT(&xenaccess->mem_event.back_ring,
                   (mem_event_sring_t *)xenaccess->mem_event.ring_page,
                   XC_PAGE_SIZE);

    /* Get domaininfo */
    xenaccess->domain_info = malloc(sizeof(xc_domaininfo_t));
    if ( xenaccess->domain_info == NULL )
    {
        ERROR("Error allocating memory for domain info");
        goto err;
    }

    rc = xc_domain_getinfolist(xenaccess->xc_handle, domain_id, 1,
                               xenaccess->domain_info);
    if ( rc != 1 )
    {
        ERROR("Error getting domain info");
        goto err;
    }

    DPRINTF("max_pages = %"PRIx64"\n", xenaccess->domain_info->max_pages);

    return xenaccess;

 err:
    xenaccess_teardown(xch, xenaccess);

 err_iface:
    return NULL;
}

int get_request(mem_event_t *mem_event, mem_event_request_t *req)
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

static int xenaccess_resume_page(xenaccess_t *paging, mem_event_response_t *rsp)
{
    int ret;

    /* Put the page info on the ring */
    ret = put_response(&paging->mem_event, rsp);
    if ( ret != 0 )
        goto out;

    /* Tell Xen page is ready */
    ret = xc_mem_access_resume(paging->xc_handle, paging->mem_event.domain_id);
    ret = xc_evtchn_notify(paging->mem_event.xce_handle,
                           paging->mem_event.port);

 out:
    return ret;
}

void usage(char* progname)
{
    fprintf(stderr,
            "Usage: %s [-m] <domain_id> write|exec|int3\n"
            "\n"
            "Logs first page writes, execs, or int3 traps that occur on the domain.\n"
            "\n"
            "-m requires this program to run, or else the domain may pause\n",
            progname);
}

int main(int argc, char *argv[])
{
    struct sigaction act;
    domid_t domain_id;
    xenaccess_t *xenaccess;
    mem_event_request_t req;
    mem_event_response_t rsp;
    int rc = -1;
    int rc1;
    xc_interface *xch;
    xenmem_access_t default_access = XENMEM_access_rwx;
    xenmem_access_t after_first_access = XENMEM_access_rwx;
    int required = 0;
    int int3 = 0;
    int shutting_down = 0;

    char* progname = argv[0];
    argv++;
    argc--;

    if ( argc == 3 && argv[0][0] == '-' )
    {
        if ( !strcmp(argv[0], "-m") )
            required = 1;
        else
        {
            usage(progname);
            return -1;
        }
        argv++;
        argc--;
    }

    if ( argc != 2 )
    {
        usage(progname);
        return -1;
    }

    domain_id = atoi(argv[0]);
    argv++;
    argc--;

    if ( !strcmp(argv[0], "write") )
    {
        default_access = XENMEM_access_rx;
        after_first_access = XENMEM_access_rwx;
    }
    else if ( !strcmp(argv[0], "exec") )
    {
        default_access = XENMEM_access_rw;
        after_first_access = XENMEM_access_rwx;
    }
    else if ( !strcmp(argv[0], "int3") )
    {
        int3 = 1;
    }
    else
    {
        usage(argv[0]);
        return -1;
    }

    xenaccess = xenaccess_init(&xch, domain_id);
    if ( xenaccess == NULL )
    {
        ERROR("Error initialising xenaccess");
        return 1;
    }

    DPRINTF("starting %s %u\n", argv[0], domain_id);

    /* ensure that if we get a signal, we'll do cleanup, then exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* Set whether the access listener is required */
    rc = xc_domain_set_access_required(xch, domain_id, required);
    if ( rc < 0 )
    {
        ERROR("Error %d setting mem_access listener required\n", rc);
        goto exit;
    }

    /* Set the default access type and convert all pages to it */
    rc = xc_set_mem_access(xch, domain_id, default_access, ~0ull, 0);
    if ( rc < 0 )
    {
        ERROR("Error %d setting default mem access type\n", rc);
        goto exit;
    }

    rc = xc_set_mem_access(xch, domain_id, default_access, 0,
                           xenaccess->domain_info->max_pages);
    if ( rc < 0 )
    {
        ERROR("Error %d setting all memory to access type %d\n", rc,
              default_access);
        goto exit;
    }

    if ( int3 )
        rc = xc_hvm_param_set(xch, domain_id, HVM_PARAM_MEMORY_EVENT_INT3, HVMPME_mode_sync);
    else
        rc = xc_hvm_param_set(xch, domain_id, HVM_PARAM_MEMORY_EVENT_INT3, HVMPME_mode_disabled);
    if ( rc < 0 )
    {
        ERROR("Error %d setting int3 mem_event\n", rc);
        goto exit;
    }

    /* Wait for access */
    for (;;)
    {
        if ( interrupted )
        {
            DPRINTF("xenaccess shutting down on signal %d\n", interrupted);

            /* Unregister for every event */
            rc = xc_set_mem_access(xch, domain_id, XENMEM_access_rwx, ~0ull, 0);
            rc = xc_set_mem_access(xch, domain_id, XENMEM_access_rwx, 0,
                                   xenaccess->domain_info->max_pages);
            rc = xc_hvm_param_set(xch, domain_id, HVM_PARAM_MEMORY_EVENT_INT3, HVMPME_mode_disabled);

            shutting_down = 1;
        }

        rc = xc_wait_for_event_or_timeout(xch, xenaccess->mem_event.xce_handle, 100);
        if ( rc < -1 )
        {
            ERROR("Error getting event");
            interrupted = -1;
            continue;
        }
        else if ( rc != -1 )
        {
            DPRINTF("Got event from Xen\n");
        }

        while ( RING_HAS_UNCONSUMED_REQUESTS(&xenaccess->mem_event.back_ring) )
        {
            xenmem_access_t access;

            rc = get_request(&xenaccess->mem_event, &req);
            if ( rc != 0 )
            {
                ERROR("Error getting request");
                interrupted = -1;
                continue;
            }

            memset( &rsp, 0, sizeof (rsp) );
            rsp.vcpu_id = req.vcpu_id;
            rsp.flags = req.flags;

            switch (req.reason) {
            case MEM_EVENT_REASON_VIOLATION:
                rc = xc_get_mem_access(xch, domain_id, req.gfn, &access);
                if (rc < 0)
                {
                    ERROR("Error %d getting mem_access event\n", rc);
                    interrupted = -1;
                    continue;
                }

                printf("PAGE ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"
                       PRIx64") gla %016"PRIx64" (valid: %c; fault in gpt: %c; fault with gla: %c) (vcpu %u)\n",
                       req.access_r ? 'r' : '-',
                       req.access_w ? 'w' : '-',
                       req.access_x ? 'x' : '-',
                       req.gfn,
                       req.offset,
                       req.gla,
                       req.gla_valid ? 'y' : 'n',
                       req.fault_in_gpt ? 'y' : 'n',
                       req.fault_with_gla ? 'y': 'n',
                       req.vcpu_id);

                if ( default_access != after_first_access )
                {
                    rc = xc_set_mem_access(xch, domain_id, after_first_access,
                                           req.gfn, 1);
                    if (rc < 0)
                    {
                        ERROR("Error %d setting gfn to access_type %d\n", rc,
                              after_first_access);
                        interrupted = -1;
                        continue;
                    }
                }


                rsp.gfn = req.gfn;
                rsp.p2mt = req.p2mt;
                break;
            case MEM_EVENT_REASON_INT3:
                printf("INT3: rip=%016"PRIx64", gfn=%"PRIx64" (vcpu %d)\n", 
                       req.gla, 
                       req.gfn,
                       req.vcpu_id);

                /* Reinject */
                rc = xc_hvm_inject_trap(
                    xch, domain_id, req.vcpu_id, 3,
                    HVMOP_TRAP_sw_exc, -1, 0, 0);
                if (rc < 0)
                {
                    ERROR("Error %d injecting int3\n", rc);
                    interrupted = -1;
                    continue;
                }

                break;
            default:
                fprintf(stderr, "UNKNOWN REASON CODE %d\n", req.reason);
            }

            rc = xenaccess_resume_page(xenaccess, &rsp);
            if ( rc != 0 )
            {
                ERROR("Error resuming page");
                interrupted = -1;
                continue;
            }
        }

        if ( shutting_down )
            break;
    }
    DPRINTF("xenaccess shut down on signal %d\n", interrupted);

exit:
    /* Tear down domain xenaccess */
    rc1 = xenaccess_teardown(xch, xenaccess);
    if ( rc1 != 0 )
        ERROR("Error tearing down xenaccess");

    if ( rc == 0 )
        rc = rc1;

    DPRINTF("xenaccess exit code %d\n", rc);
    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
