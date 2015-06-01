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

#ifdef XC_WANT_COMPAT_GNTTAB_API

typedef struct xengntdev_handle xc_gnttab;

xc_gnttab *xc_gnttab_open(xentoollog_logger *logger,
                          unsigned open_flags);
int xc_gnttab_close(xc_gnttab *xcg);
void *xc_gnttab_map_grant_ref(xc_gnttab *xcg,
                              uint32_t domid,
                              uint32_t ref,
                              int prot);
void *xc_gnttab_map_grant_refs(xc_gnttab *xcg,
                               uint32_t count,
                               uint32_t *domids,
                               uint32_t *refs,
                               int prot);
void *xc_gnttab_map_domain_grant_refs(xc_gnttab *xcg,
                                      uint32_t count,
                                      uint32_t domid,
                                      uint32_t *refs,
                                      int prot);
void *xc_gnttab_map_grant_ref_notify(xc_gnttab *xcg,
                                     uint32_t domid,
                                     uint32_t ref,
                                     int prot,
                                     uint32_t notify_offset,
                                     evtchn_port_t notify_port);
int xc_gnttab_munmap(xc_gnttab *xcg,
                     void *start_address,
                     uint32_t count);
int xc_gnttab_set_max_grants(xc_gnttab *xcg,
                             uint32_t count);

typedef struct xengntdev_handle xc_gntshr;

xc_gntshr *xc_gntshr_open(xentoollog_logger *logger,
                          unsigned open_flags);
int xc_gntshr_close(xc_gntshr *xcg);
void *xc_gntshr_share_pages(xc_gntshr *xcg, uint32_t domid,
                            int count, uint32_t *refs, int writable);
void *xc_gntshr_share_page_notify(xc_gntshr *xcg, uint32_t domid,
                                  uint32_t *ref, int writable,
                                  uint32_t notify_offset,
                                  evtchn_port_t notify_port);
int xc_gntshr_munmap(xc_gntshr *xcg, void *start_address, uint32_t count);

#endif /* XC_WANT_COMPAT_GNTTAB_API */

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
