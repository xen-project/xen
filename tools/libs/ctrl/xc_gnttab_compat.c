/*
 * Compat shims for use of 3rd party consumers of libxenctrl xc_gnt{tab,shr}
 * functionality which has been split into separate libraries.
 */

#include <xengnttab.h>

#define XC_WANT_COMPAT_GNTTAB_API
#include "xenctrl.h"

xc_gnttab *xc_gnttab_open(xentoollog_logger *logger,
                          unsigned open_flags)
{
    return xengnttab_open(logger, open_flags);
}

int xc_gnttab_close(xc_gnttab *xcg)
{
    return xengnttab_close(xcg);
}

void *xc_gnttab_map_grant_ref(xc_gnttab *xcg,
                              uint32_t domid,
                              uint32_t ref,
                              int prot)
{
    return xengnttab_map_grant_ref(xcg, domid, ref, prot);
}

void *xc_gnttab_map_grant_refs(xc_gnttab *xcg,
                               uint32_t count,
                               uint32_t *domids,
                               uint32_t *refs,
                               int prot)
{
    return xengnttab_map_grant_refs(xcg, count, domids, refs, prot);
}

void *xc_gnttab_map_domain_grant_refs(xc_gnttab *xcg,
                                      uint32_t count,
                                      uint32_t domid,
                                      uint32_t *refs,
                                      int prot)
{
    return xengnttab_map_domain_grant_refs(xcg, count, domid, refs, prot);
}

void *xc_gnttab_map_grant_ref_notify(xc_gnttab *xcg,
                                     uint32_t domid,
                                     uint32_t ref,
                                     int prot,
                                     uint32_t notify_offset,
                                     evtchn_port_t notify_port)
{
    return xengnttab_map_grant_ref_notify(xcg, domid, ref, prot,
                                          notify_offset, notify_port);
}

int xc_gnttab_munmap(xc_gnttab *xcg,
                     void *start_address,
                     uint32_t count)
{
    return xengnttab_unmap(xcg, start_address, count);
}

int xc_gnttab_set_max_grants(xc_gnttab *xcg,
                             uint32_t count)
{
    return xengnttab_set_max_grants(xcg, count);
}

xc_gntshr *xc_gntshr_open(xentoollog_logger *logger,
                          unsigned open_flags)
{
    return xengntshr_open(logger, open_flags);
}

int xc_gntshr_close(xc_gntshr *xcg)
{
    return xengntshr_close(xcg);
}

void *xc_gntshr_share_pages(xc_gntshr *xcg, uint32_t domid,
                            int count, uint32_t *refs, int writable)
{
    return xengntshr_share_pages(xcg, domid, count, refs, writable);
}

void *xc_gntshr_share_page_notify(xc_gntshr *xcg, uint32_t domid,
                                  uint32_t *ref, int writable,
                                  uint32_t notify_offset,
                                  evtchn_port_t notify_port)
{
    return xengntshr_share_page_notify(xcg, domid, ref, writable,
                                       notify_offset, notify_port);
}

int xc_gntshr_munmap(xc_gntshr *xcg, void *start_address, uint32_t count)
{
    return xengntshr_unshare(xcg, start_address, count);
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
