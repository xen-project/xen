/* SPDX-License-Identifier: GPL-2.0-only */

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <xenctrl.h>
#include <xenforeignmemory.h>
#include <xenevtchn.h>

#include <xen/vm_event.h>

#define DEFAULT_SLOT_SIZE 1024U
#define DEFAULT_ASYNC_RING_PAGES 16U

static volatile sig_atomic_t interrupted;

static void close_handler(int signum)
{
    interrupted = 1;
}

enum event_kind {
    EV_NONE = 0,
    EV_CPUID,
    EV_BREAKPOINT,
    EV_SINGLESTEP,
    EV_CR3,
};

static enum event_kind parse_event(const char *s)
{
    if ( !strcmp(s, "cpuid") )       return EV_CPUID;
    if ( !strcmp(s, "breakpoint") )  return EV_BREAKPOINT;
    if ( !strcmp(s, "singlestep") )  return EV_SINGLESTEP;
    if ( !strcmp(s, "cr3") )         return EV_CR3;
    return EV_NONE;
}

static int enable_event(xc_interface *xch, uint32_t domid,
                        enum event_kind kind, bool async)
{
    switch ( kind )
    {
    case EV_CPUID:
        return xc_monitor_cpuid(xch, domid, 1);
    case EV_BREAKPOINT:
        return xc_monitor_software_breakpoint(xch, domid, 1);
    case EV_SINGLESTEP:
        return xc_monitor_singlestep(xch, domid, 1);
    case EV_CR3:
        return xc_monitor_write_ctrlreg(xch, domid, VM_EVENT_X86_CR3,
                                        1, async ? 0 : 1, 0, 0);
    default:
        return -EINVAL;
    }
}

static int disable_event(xc_interface *xch, uint32_t domid,
                         enum event_kind kind)
{
    switch ( kind )
    {
    case EV_CPUID:
        return xc_monitor_cpuid(xch, domid, 0);
    case EV_BREAKPOINT:
        return xc_monitor_software_breakpoint(xch, domid, 0);
    case EV_SINGLESTEP:
        return xc_monitor_singlestep(xch, domid, 0);
    case EV_CR3:
        return xc_monitor_write_ctrlreg(xch, domid, VM_EVENT_X86_CR3,
                                        0, 1, ~0ULL, 0);
    default:
        return 0;
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s <domid> <event> [max-events] [--async]\n"
            "  events: cpuid | breakpoint | singlestep | cr3\n"
            "  --async: also allocate the v2 async ring; configure\n"
            "           supported events (cr3) as async-delivery\n",
            prog);
}

/*
 * Read one async slot under Linux-style seqcount discipline.
 * Returns 0 if the body was read atomically w.r.t. the producer,
 * -1 if torn after a small retry budget (slot dropped, advance anyway).
 */
static int read_async_slot(struct vm_event_async_slot *slot,
                           vm_event_request_t *out)
{
    uint32_t s1, s2;
    int retries = 4;

    while ( retries-- > 0 )
    {
        s1 = __atomic_load_n(&slot->seqcount, __ATOMIC_ACQUIRE);
        if ( s1 & 1U )
            continue;
        memcpy(out, &slot->req, sizeof(*out));
        s2 = __atomic_load_n(&slot->seqcount, __ATOMIC_ACQUIRE);
        if ( s1 == s2 )
            return 0;
    }
    return -1;
}

static inline void respond_to(struct vm_event_sync_slot *slot,
                              uint32_t vcpu_id)
{
    memset(&slot->rsp, 0, sizeof(slot->rsp));
    slot->rsp.version = VM_EVENT_INTERFACE_VERSION;
    slot->rsp.vcpu_id = vcpu_id;
    slot->rsp.reason  = slot->req.reason;
    slot->rsp.flags   = slot->req.flags & VM_EVENT_FLAG_VCPU_PAUSED;
    slot->response_seq = slot->request_seq;
    __atomic_store_n(&slot->state, VM_EVENT_SYNC_STATE_RESPONSE,
                     __ATOMIC_RELEASE);
}

int main(int argc, char **argv)
{
    xc_interface *xch = NULL;
    xenforeignmemory_handle *fh = NULL;
    xenevtchn_handle *xce = NULL;
    xenforeignmemory_resource_handle *fres = NULL;
    xenforeignmemory_resource_handle *async_fres = NULL;
    void *region = NULL;
    void *async_region = NULL;
    struct vm_event_sync_header *hdr = NULL;
    struct vm_event_async_header *async_hdr = NULL;
    int *local_ports = NULL;
    int *vcpu_by_local_port = NULL;
    int max_local_port = 0;
    int async_local_port = -1;
    uint32_t async_cons_local = 0;
    uint32_t domid = 0;
    enum event_kind kind = EV_NONE;
    const char *event_name = NULL;
    long max_events = -1;
    long count = 0;
    long async_count = 0;
    long async_torn = 0;
    size_t region_bytes = 0;
    size_t async_region_bytes = 0;
    unsigned int nr_pages = 0, nr_vcpus = 0, slot_size = 0;
    unsigned int async_nr_pages = 0;
    uint32_t async_ring_pages_req = 0;
    bool monitor_enabled = false;
    bool event_enabled = false;
    bool async = false;
    int positional = 0;
    unsigned int i;
    int exit_code = 1;
    int rc;

    struct sigaction act = { .sa_handler = close_handler };
    sigemptyset(&act.sa_mask);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGHUP,  &act, NULL);

    if ( argc < 3 )
    {
        usage(argv[0]);
        return 1;
    }

    for ( i = 1; i < (unsigned)argc; i++ )
    {
        const char *a = argv[i];

        if ( !strcmp(a, "--async") )
        {
            async = true;
        }
        else if ( positional == 0 )
        {
            domid = (uint32_t)atoi(a);
            positional++;
        }
        else if ( positional == 1 )
        {
            event_name = a;
            kind = parse_event(a);
            if ( kind == EV_NONE )
            {
                fprintf(stderr, "unknown event type: %s\n", a);
                usage(argv[0]);
                return 1;
            }
            positional++;
        }
        else if ( positional == 2 )
        {
            max_events = atol(a);
            positional++;
        }
        else
        {
            usage(argv[0]);
            return 1;
        }
    }
    if ( positional < 2 )
    {
        usage(argv[0]);
        return 1;
    }
    async_ring_pages_req = async ? DEFAULT_ASYNC_RING_PAGES : 0;

    xch = xc_interface_open(NULL, NULL, 0);
    if ( !xch ) { perror("xc_interface_open"); goto out; }

    fh = xenforeignmemory_open(NULL, 0);
    if ( !fh ) { perror("xenforeignmemory_open"); goto out; }

    xce = xenevtchn_open(NULL, 0);
    if ( !xce ) { perror("xenevtchn_open"); goto out; }

    rc = xc_monitor_setup(xch, domid,
                          XEN_VM_EVENT_SETUP_SYNC |
                          (async ? XEN_VM_EVENT_SETUP_ASYNC : 0),
                          DEFAULT_SLOT_SIZE, async_ring_pages_req);
    if ( rc )
    {
        perror("xc_monitor_setup");
        goto out;
    }
    monitor_enabled = true;

    rc = enable_event(xch, domid, kind, async);
    if ( rc )
    {
        fprintf(stderr, "enable_event(%s): %s\n",
                event_name, strerror(-rc));
        goto out;
    }
    event_enabled = true;

    rc = xenforeignmemory_resource_size(
            fh, domid, XENMEM_resource_vm_event_sync, 0, &region_bytes);
    if ( rc )
    {
        perror("xenforeignmemory_resource_size");
        goto out;
    }
    nr_pages = region_bytes >> XC_PAGE_SHIFT;
    if ( nr_pages == 0 )
    {
        fprintf(stderr, "region size query returned 0 pages\n");
        goto out;
    }

    fres = xenforeignmemory_map_resource(
            fh, domid, XENMEM_resource_vm_event_sync, 0, 0, nr_pages,
            &region, PROT_READ | PROT_WRITE, 0);
    if ( !fres )
    {
        perror("xenforeignmemory_map_resource");
        goto out;
    }

    hdr = region;
    if ( vm_event_sync_header_valid(hdr, VM_EVENT_SYNC_VERSION) < 0 )
    {
        fprintf(stderr, "sync header invalid (magic=%#x version=%u)\n",
                hdr->magic, hdr->version);
        goto out;
    }
    nr_vcpus = hdr->nr_vcpus;
    slot_size = hdr->slot_size;
    (void)slot_size;

    local_ports = calloc(nr_vcpus, sizeof(*local_ports));
    if ( !local_ports ) { perror("calloc"); goto out; }

    for ( i = 0; i < nr_vcpus; i++ )
    {
        uint32_t remote_port = vm_event_sync_port(region, i);
        int lp = xenevtchn_bind_interdomain(xce, domid, remote_port);
        if ( lp < 0 )
        {
            fprintf(stderr, "xenevtchn_bind_interdomain vcpu_id=%u: %s\n",
                    i, strerror(errno));
            goto out;
        }
        local_ports[i] = lp;
        if ( lp > max_local_port )
            max_local_port = lp;
    }

    if ( async )
    {
        rc = xenforeignmemory_resource_size(
                fh, domid, XENMEM_resource_vm_event_async, 0,
                &async_region_bytes);
        if ( rc )
        {
            perror("xenforeignmemory_resource_size(async)");
            goto out;
        }
        async_nr_pages = async_region_bytes >> XC_PAGE_SHIFT;
        if ( async_nr_pages == 0 )
        {
            fprintf(stderr, "async region size query returned 0 pages\n");
            goto out;
        }

        async_fres = xenforeignmemory_map_resource(
                fh, domid, XENMEM_resource_vm_event_async, 0, 0,
                async_nr_pages, &async_region, PROT_READ | PROT_WRITE, 0);
        if ( !async_fres )
        {
            perror("xenforeignmemory_map_resource(async)");
            goto out;
        }

        async_hdr = async_region;
        if ( vm_event_async_header_valid(async_hdr,
                                         VM_EVENT_ASYNC_VERSION) < 0 )
        {
            fprintf(stderr,
                    "async header invalid (magic=%#x version=%u)\n",
                    async_hdr->magic, async_hdr->version);
            goto out;
        }

        async_local_port = xenevtchn_bind_interdomain(xce, domid,
                                                     async_hdr->evtchn_port);
        if ( async_local_port < 0 )
        {
            fprintf(stderr, "xenevtchn_bind_interdomain(async): %s\n",
                    strerror(errno));
            goto out;
        }
        if ( async_local_port > max_local_port )
            max_local_port = async_local_port;

        async_cons_local = async_hdr->cons_idx;

        printf("async ring: nr_slots=%u slot_size=%u "
               "max_outstanding=%u port=%u\n",
               async_hdr->nr_slots, async_hdr->slot_size,
               async_hdr->max_outstanding, async_hdr->evtchn_port);
    }

    vcpu_by_local_port = malloc((max_local_port + 1) *
                                sizeof(*vcpu_by_local_port));
    if ( !vcpu_by_local_port ) { perror("malloc"); goto out; }
    for ( i = 0; i <= (unsigned)max_local_port; i++ )
        vcpu_by_local_port[i] = -1;
    for ( i = 0; i < nr_vcpus; i++ )
        vcpu_by_local_port[local_ports[i]] = (int)i;

    while ( !interrupted && (max_events < 0 || count < max_events) )
    {
        struct vm_event_sync_slot *slot;
        unsigned int vcpu_id;
        int local_port = xenevtchn_pending(xce);

        if ( local_port < 0 )
        {
            if ( errno == EINTR )
                continue;
            perror("xenevtchn_pending");
            break;
        }
        xenevtchn_unmask(xce, local_port);

        if ( async && local_port == async_local_port )
        {
            uint32_t prod;

            prod = __atomic_load_n(&async_hdr->prod_idx, __ATOMIC_ACQUIRE);
            while ( async_cons_local != prod )
            {
                struct vm_event_async_slot *as =
                    vm_event_async_slot(async_region, async_cons_local);
                vm_event_request_t req;

                if ( read_async_slot(as, &req) == 0 )
                {
                    printf("[async %ld] vcpu=%u reason=%u flags=%#x\n",
                           async_count, req.vcpu_id, req.reason,
                           req.flags);
                    async_count++;
                }
                else
                {
                    async_torn++;
                }
                async_cons_local++;
                count++;
                if ( max_events >= 0 && count >= max_events )
                    break;
            }

            __atomic_store_n(&async_hdr->cons_idx, async_cons_local,
                             __ATOMIC_RELEASE);
            if ( xenevtchn_notify(xce, async_local_port) < 0 )
                perror("xenevtchn_notify(async)");
            continue;
        }

        if ( local_port > max_local_port ||
             vcpu_by_local_port[local_port] < 0 )
        {
            fprintf(stderr, "spurious port %d (no matching vcpu)\n",
                    local_port);
            continue;
        }
        vcpu_id = (unsigned int)vcpu_by_local_port[local_port];

        slot = vm_event_sync_slot(region, vcpu_id);

        if ( slot->state != VM_EVENT_SYNC_STATE_REQUEST )
        {
            fprintf(stderr,
                    "vcpu %u: notification with state=%u (want REQUEST=%u)\n",
                    vcpu_id, slot->state, VM_EVENT_SYNC_STATE_REQUEST);
            continue;
        }

        printf("[%ld] vcpu=%u reason=%u flags=%#x request_seq=%u\n",
               count, vcpu_id, slot->req.reason, slot->req.flags,
               slot->request_seq);

        respond_to(slot, vcpu_id);

        if ( xenevtchn_notify(xce, local_port) < 0 )
            perror("xenevtchn_notify");

        count++;
    }

    printf("xen-access-v2: stopped after %ld event(s)"
           " (async=%ld, async_torn=%ld)\n",
           count, async_count, async_torn);
    exit_code = 0;

 out:
    if ( async_local_port >= 0 && xce )
        xenevtchn_unbind(xce, async_local_port);
    if ( local_ports )
    {
        for ( i = 0; i < nr_vcpus; i++ )
            if ( local_ports[i] > 0 )
                xenevtchn_unbind(xce, local_ports[i]);
    }
    free(vcpu_by_local_port);
    free(local_ports);

    if ( async_fres )
        xenforeignmemory_unmap_resource(fh, async_fres);
    if ( fres )
        xenforeignmemory_unmap_resource(fh, fres);

    if ( event_enabled )
        disable_event(xch, domid, kind);
    if ( monitor_enabled )
        xc_monitor_disable(xch, domid);

    if ( xce )
        xenevtchn_close(xce);
    if ( fh )
        xenforeignmemory_close(fh);
    if ( xch )
        xc_interface_close(xch);

    return exit_code;
}
