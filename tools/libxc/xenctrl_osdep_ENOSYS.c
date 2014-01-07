/* Dummy backend which just logs and returns ENOSYS. */

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>

#include "xenctrl.h"
#include "xenctrlosdep.h"

#define IPRINTF(_x, _f, _a...) xc_osdep_log(_x,XTL_INFO,0, _f , ## _a)

#define ERROR(_x, _m, _a...)  xc_osdep_log(_x,XTL_ERROR,XC_INTERNAL_ERROR,_m , ## _a )
#define PERROR(_x, _m, _a...) xc_osdep_log(_x,XTL_ERROR,XC_INTERNAL_ERROR,_m \
                  " (%d = %s)", ## _a , errno, xc_strerror(xch, errno))

static xc_osdep_handle ENOSYS_privcmd_open(xc_interface *xch)
{
    IPRINTF(xch, "ENOSYS_privcmd: opening handle %p\n", (void *)1);
    return (xc_osdep_handle)1; /*dummy*/
}

static int ENOSYS_privcmd_close(xc_interface *xch, xc_osdep_handle h)
{
    IPRINTF(xch, "ENOSYS_privcmd: closing handle %p\n", h);
    return 0;
}

static int ENOSYS_privcmd_hypercall(xc_interface *xch, xc_osdep_handle h, privcmd_hypercall_t *hypercall)
{
    IPRINTF(xch, "ENOSYS_privcmd %p: hypercall: %02lld(%#llx,%#llx,%#llx,%#llx,%#llx)\n",
            h, hypercall->op,
            hypercall->arg[0], hypercall->arg[1], hypercall->arg[2],
            hypercall->arg[3], hypercall->arg[4]);
    return -ENOSYS;
}

static void *ENOSYS_privcmd_map_foreign_batch(xc_interface *xch, xc_osdep_handle h, uint32_t dom, int prot,
                                      xen_pfn_t *arr, int num)
{
    IPRINTF(xch, "ENOSYS_privcmd %p: map_foreign_batch: dom%d prot %#x arr %p num %d\n", h, dom, prot, arr, num);
    return MAP_FAILED;
}

static void *ENOSYS_privcmd_map_foreign_bulk(xc_interface *xch, xc_osdep_handle h, uint32_t dom, int prot,
                                     const xen_pfn_t *arr, int *err, unsigned int num)
{
    IPRINTF(xch, "ENOSYS_privcmd %p: map_foreign_buld: dom%d prot %#x arr %p err %p num %d\n", h, dom, prot, arr, err, num);
    return MAP_FAILED;
}

static void *ENOSYS_privcmd_map_foreign_range(xc_interface *xch, xc_osdep_handle h, uint32_t dom, int size, int prot,
                                      unsigned long mfn)
{
    IPRINTF(xch, "ENOSYS_privcmd %p: map_foreign_range: dom%d size %#x prot %#x mfn %ld\n", h, dom, size, prot, mfn);
    return MAP_FAILED;
}

static void *ENOSYS_privcmd_map_foreign_ranges(xc_interface *xch, xc_osdep_handle h, uint32_t dom, size_t size, int prot,
                                       size_t chunksize, privcmd_mmap_entry_t entries[],
                                       int nentries)
{
    IPRINTF(xch, "ENOSYS_privcmd %p: map_foreign_ranges: dom%d size %zd prot %#x chunksize %zd entries %p num %d\n", h, dom, size, prot, chunksize, entries, nentries);
    return MAP_FAILED;
}

static struct xc_osdep_ops ENOSYS_privcmd_ops =
{
    .open      = &ENOSYS_privcmd_open,
    .close     = &ENOSYS_privcmd_close,
    .u.privcmd   = {
        .hypercall = &ENOSYS_privcmd_hypercall,

        .map_foreign_batch = &ENOSYS_privcmd_map_foreign_batch,
        .map_foreign_bulk = &ENOSYS_privcmd_map_foreign_bulk,
        .map_foreign_range = &ENOSYS_privcmd_map_foreign_range,
        .map_foreign_ranges = &ENOSYS_privcmd_map_foreign_ranges,
    }
};

static xc_osdep_handle ENOSYS_evtchn_open(xc_interface *xce)
{
    IPRINTF(xce, "ENOSYS_evtchn: opening handle %p\n", (void *)1);
    return (xc_osdep_handle)2; /*dummy*/
}

static int ENOSYS_evtchn_close(xc_interface *xce, xc_osdep_handle h)
{
    IPRINTF(xce, "ENOSYS_evtchn: closing handle %p\n", h);
    return 0;
}

static int ENOSYS_evtchn_fd(xc_interface *xce, xc_osdep_handle h)
{
    IPRINTF(xce, "ENOSYS_fd %p: fd\n", h);
    return (int)h;
}

static int ENOSYS_evtchn_notify(xc_interface *xce, xc_osdep_handle h, evtchn_port_t port)
{
    IPRINTF(xce, "ENOSYS_evtchn %p: notify: %d\n", h, port);
    return -ENOSYS;
}

static int ENOSYS_evtchn_bind_unbound_port(xc_interface *xce, xc_osdep_handle h, int domid)
{
    IPRINTF(xce, "ENOSYS_evtchn %p: bind_unbound_port: dom%d\n", h, domid);
    return -ENOSYS;
}


static int ENOSYS_evtchn_bind_interdomain(xc_interface *xce, xc_osdep_handle h, int domid, evtchn_port_t remote_port)
{
    IPRINTF(xce, "ENOSYS_evtchn %p: bind_interdomain: dmo%d %d\n", h, domid, remote_port);
    return -ENOSYS;
}


static int ENOSYS_evtchn_bind_virq(xc_interface *xce, xc_osdep_handle h, unsigned int virq)
{
    IPRINTF(xce, "ENOSYS_evtchn %p: bind_virq: %d\n", h, virq);
    return -ENOSYS;
}


static int ENOSYS_evtchn_unbind(xc_interface *xce, xc_osdep_handle h, evtchn_port_t port)
{
    IPRINTF(xce, "ENOSYS_evtchn %p: unbind: %d\n", h, port);
    return -ENOSYS;
}


static evtchn_port_or_error_t ENOSYS_evtchn_pending(xc_interface *xce, xc_osdep_handle h)
{
    IPRINTF(xce, "ENOSYS_evtchn %p: pending\n", h);
    return -ENOSYS;
}

static int ENOSYS_evtchn_unmask(xc_interface *xce, xc_osdep_handle h, evtchn_port_t port)
{
    IPRINTF(xce, "ENOSYS_evtchn %p: unmask: %d\n", h, port);
    return -ENOSYS;
}

static struct xc_osdep_ops ENOSYS_evtchn_ops = {
    .open = &ENOSYS_evtchn_open,
    .close = &ENOSYS_evtchn_close,

    .u.evtchn = {
        .fd = &ENOSYS_evtchn_fd,

        .notify = &ENOSYS_evtchn_notify,

        .bind_unbound_port = &ENOSYS_evtchn_bind_unbound_port,
        .bind_interdomain = &ENOSYS_evtchn_bind_interdomain,
        .bind_virq = &ENOSYS_evtchn_bind_virq,

        .unbind = &ENOSYS_evtchn_unbind,

        .pending = &ENOSYS_evtchn_pending,
        .unmask = &ENOSYS_evtchn_unmask,
    },
};

static struct xc_osdep_ops * ENOSYS_osdep_init(xc_interface *xch, enum xc_osdep_type type)
{
    struct xc_osdep_ops *ops;

    if (getenv("ENOSYS") == NULL)
    {
        PERROR(xch, "ENOSYS: not configured\n");
        return NULL;
    }

    switch ( type )
    {
    case XC_OSDEP_PRIVCMD:
        ops = &ENOSYS_privcmd_ops;
        break;
    case XC_OSDEP_EVTCHN:
        ops = &ENOSYS_evtchn_ops;
        break;
    default:
        ops = NULL;
        break;
    }

    IPRINTF(xch, "ENOSYS_osdep_init: initialising handle ops at %p\n", ops);

    return ops;
}

xc_osdep_info_t xc_osdep_info = {
    .name = "Pessimistic ENOSYS OS interface",
    .init = &ENOSYS_osdep_init,
    .fake = 1,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
