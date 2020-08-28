/*
 * Compat shims for use of 3rd party consumers of libxenctrl xc_evtchn
 * functionality which has been split into separate libraries.
 */

#include <xenevtchn.h>

#define XC_WANT_COMPAT_EVTCHN_API
#include "xenctrl.h"

xc_evtchn *xc_evtchn_open(xentoollog_logger *logger,
                          unsigned open_flags)
{
    return xenevtchn_open(logger, open_flags);
}

int xc_evtchn_close(xc_evtchn *xce)
{
    return xenevtchn_close(xce);
}

int xc_evtchn_fd(xc_evtchn *xce)
{
    return xenevtchn_fd(xce);
}

int xc_evtchn_notify(xc_evtchn *xce, evtchn_port_t port)
{
    return xenevtchn_notify(xce, port);
}

evtchn_port_or_error_t
xc_evtchn_bind_unbound_port(xc_evtchn *xce, uint32_t domid)
{
    return xenevtchn_bind_unbound_port(xce, domid);
}

evtchn_port_or_error_t
xc_evtchn_bind_interdomain(xc_evtchn *xce, uint32_t domid,
                           evtchn_port_t remote_port)
{
    return xenevtchn_bind_interdomain(xce, domid, remote_port);
}

evtchn_port_or_error_t
xc_evtchn_bind_virq(xc_evtchn *xce, unsigned int virq)
{
    return xenevtchn_bind_virq(xce, virq);
}

int xc_evtchn_unbind(xc_evtchn *xce, evtchn_port_t port)
{
    return xenevtchn_unbind(xce, port);
}

evtchn_port_or_error_t
xc_evtchn_pending(xc_evtchn *xce)
{
    return xenevtchn_pending(xce);
}

int xc_evtchn_unmask(xc_evtchn *xce, evtchn_port_t port)
{
    return xenevtchn_unmask(xce, port);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
