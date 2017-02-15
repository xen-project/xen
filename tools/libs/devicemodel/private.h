#ifndef XENDEVICEMODEL_PRIVATE_H
#define XENDEVICEMODEL_PRIVATE_H

#include <xentoollog.h>
#include <xendevicemodel.h>

struct xendevicemodel_handle {
    xentoollog_logger *logger, *logger_tofree;
    unsigned int flags;
};

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
