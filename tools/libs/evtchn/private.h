#ifndef XENEVTCHN_PRIVATE_H
#define XENEVTCHN_PRIVATE_H

#include <xentoollog.h>
#include <xenevtchn.h>

struct xenevtchn_handle {
    xentoollog_logger *logger, *logger_tofree;
    int fd;
};

int osdep_evtchn_open(xenevtchn_handle *xce);
int osdep_evtchn_close(xenevtchn_handle *xce);

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
