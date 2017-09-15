#ifndef XENDEVICEMODEL_PRIVATE_H
#define XENDEVICEMODEL_PRIVATE_H

#define __XEN_TOOLS__ 1

#include <xentoollog.h>
#include <xendevicemodel.h>
#include <xencall.h>

#include <xentoolcore_internal.h>

struct xendevicemodel_handle {
    xentoollog_logger *logger, *logger_tofree;
    unsigned int flags;
    xencall_handle *xcall;
    int fd;
    Xentoolcore__Active_Handle tc_ah;
};

struct xendevicemodel_buf {
    void *ptr;
    size_t size;
};

int xendevicemodel_xcall(xendevicemodel_handle *dmod,
                         domid_t domid, unsigned int nr_bufs,
                         struct xendevicemodel_buf bufs[]);

int osdep_xendevicemodel_open(xendevicemodel_handle *dmod);
int osdep_xendevicemodel_close(xendevicemodel_handle *dmod);
int osdep_xendevicemodel_op(xendevicemodel_handle *dmod,
                            domid_t domid, unsigned int nr_bufs,
                            struct xendevicemodel_buf bufs[]);

int osdep_xendevicemodel_restrict(
    xendevicemodel_handle *dmod, domid_t domid);

#define PERROR(_f...) \
    xtl_log(dmod->logger, XTL_ERROR, errno, "xendevicemodel", _f)

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
