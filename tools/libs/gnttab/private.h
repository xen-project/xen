#ifndef XENGNTTAB_PRIVATE_H
#define XENGNTTAB_PRIVATE_H

#include <xentoollog.h>
#include <xentoolcore_internal.h>
#include <xengnttab.h>

/* Set of macros/defines used by both Linux and FreeBSD */
#define ROUNDUP(_x,_w) (((unsigned long)(_x)+(1UL<<(_w))-1) & ~((1UL<<(_w))-1))

#define GTERROR(_l, _f...) xtl_log(_l, XTL_ERROR, errno, "gnttab", _f)
#define GSERROR(_l, _f...) xtl_log(_l, XTL_ERROR, errno, "gntshr", _f)

struct xengntdev_handle {
    xentoollog_logger *logger, *logger_tofree;
    int fd;
    Xentoolcore__Active_Handle tc_ah;
};

int osdep_gnttab_open(xengnttab_handle *xgt);
int osdep_gnttab_close(xengnttab_handle *xgt);

int osdep_gnttab_set_max_grants(xengnttab_handle *xgt, uint32_t count);

#define XENGNTTAB_GRANT_MAP_SINGLE_DOMAIN 0x1
void *osdep_gnttab_grant_map(xengnttab_handle *xgt,
                             uint32_t count, int flags, int prot,
                             uint32_t *domids, uint32_t *refs,
                             uint32_t notify_offset,
                             evtchn_port_t notify_port);
int osdep_gnttab_unmap(xengnttab_handle *xgt,
                       void *start_address,
                       uint32_t count);
int osdep_gnttab_grant_copy(xengnttab_handle *xgt,
                            uint32_t count,
                            xengnttab_grant_copy_segment_t *segs);

int osdep_gntshr_open(xengntshr_handle *xgs);
int osdep_gntshr_close(xengntshr_handle *xgs);

void *osdep_gntshr_share_pages(xengntshr_handle *xgs,
                               uint32_t domid, int count,
                               uint32_t *refs, int writable,
                               uint32_t notify_offset,
                               evtchn_port_t notify_port);
int osdep_gntshr_unshare(xengntshr_handle *xgs,
                         void *start_address, uint32_t count);

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
