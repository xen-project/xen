/*
 * Compat shims for use of 3rd party consumers of libxenctrl
 * functionality which has been split into separate libraries.
 *
 * New code should use the separate libraries.
 *
 * Each interface must be opted-into separately by defining:
 *
 * XC_WANT_COMPAT_EVTCHN_API
 *  - Functions relating to /dev/xen/evtchn
 */
#ifndef XENCTRL_COMPAT_H
#define XENCTRL_COMPAT_H

#ifdef XC_WANT_COMPAT_EVTCHN_API

typedef struct xenevtchn_handle xc_evtchn;

xc_evtchn *xc_evtchn_open(xentoollog_logger *logger,
                             unsigned open_flags);
int xc_evtchn_close(xc_evtchn *xce);
int xc_evtchn_fd(xc_evtchn *xce);
int xc_evtchn_notify(xc_evtchn *xce, evtchn_port_t port);
evtchn_port_or_error_t
xc_evtchn_bind_unbound_port(xc_evtchn *xce, int domid);
evtchn_port_or_error_t
xc_evtchn_bind_interdomain(xc_evtchn *xce, int domid,
                           evtchn_port_t remote_port);
evtchn_port_or_error_t
xc_evtchn_bind_virq(xc_evtchn *xce, unsigned int virq);
int xc_evtchn_unbind(xc_evtchn *xce, evtchn_port_t port);
evtchn_port_or_error_t
xc_evtchn_pending(xc_evtchn *xce);
int xc_evtchn_unmask(xc_evtchn *xce, evtchn_port_t port);

#endif /* XC_WANT_COMPAT_EVTCHN_API */

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
