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
                        enum event_kind kind)
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
                                        1, 1, 0, 0);
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
            "Usage: %s <domid> <event> [max-events]\n"
            "  events: cpuid | breakpoint | singlestep | cr3\n",
            prog);
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
    void *region = NULL;
    struct vm_event_sync_header *hdr = NULL;
    int *local_ports = NULL;
    int *vcpu_by_local_port = NULL;
    int max_local_port = 0;
    uint32_t domid;
    enum event_kind kind = EV_NONE;
    long max_events = -1;
    long count = 0;
    size_t region_bytes = 0;
    unsigned int nr_pages = 0, nr_vcpus = 0, slot_size = 0;
    bool monitor_enabled = false;
    bool event_enabled = false;
    unsigned int i;
    int exit_code = 1;
    int rc;

    struct sigaction act = { .sa_handler = close_handler };
    sigemptyset(&act.sa_mask);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGHUP,  &act, NULL);

    if ( argc < 3 || argc > 4 )
    {
        usage(argv[0]);
        return 1;
    }
    domid = (uint32_t)atoi(argv[1]);
    kind = parse_event(argv[2]);
    if ( kind == EV_NONE )
    {
        fprintf(stderr, "unknown event type: %s\n", argv[2]);
        usage(argv[0]);
        return 1;
    }
    if ( argc == 4 )
        max_events = atol(argv[3]);

    xch = xc_interface_open(NULL, NULL, 0);
    if ( !xch ) { perror("xc_interface_open"); goto out; }

    fh = xenforeignmemory_open(NULL, 0);
    if ( !fh ) { perror("xenforeignmemory_open"); goto out; }

    xce = xenevtchn_open(NULL, 0);
    if ( !xce ) { perror("xenevtchn_open"); goto out; }

    rc = xc_monitor_setup(xch, domid, XEN_VM_EVENT_SETUP_SYNC,
                          DEFAULT_SLOT_SIZE, 0);
    if ( rc )
    {
        perror("xc_monitor_setup");
        goto out;
    }
    monitor_enabled = true;

    rc = enable_event(xch, domid, kind);
    if ( rc )
    {
        fprintf(stderr, "enable_event(%s): %s\n", argv[2], strerror(-rc));
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

    printf("xen-access-v2: stopped after %ld event(s)\n", count);
    exit_code = 0;

 out:
    if ( local_ports )
    {
        for ( i = 0; i < nr_vcpus; i++ )
            if ( local_ports[i] > 0 )
                xenevtchn_unbind(xce, local_ports[i]);
    }
    free(vcpu_by_local_port);
    free(local_ports);

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
