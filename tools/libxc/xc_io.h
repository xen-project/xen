#ifndef __XC_XC_IO_H__
#define __XC_XC_IO_H__

#include <errno.h>
#include "xc_private.h"
#include "iostream.h"

typedef struct XcIOContext {
    u32 domain;
    unsigned flags;
    IOStream *io;
    IOStream *info;
    IOStream *err;
    char *vmconfig;
    int vmconfig_n;
    int (*suspend)(void *data, u32 domain);
    int (*configure)(void *data, u32 domain, char *vmconfig, int vmconfig_n);
    void *data;
} XcIOContext;

static inline int xcio_suspend_domain(XcIOContext *ctxt){
    int err = 0;

    if(ctxt->suspend){
        err = ctxt->suspend(ctxt->data, ctxt->domain);
    } else {
        err = -EINVAL;
    }
    return err;
}

static inline int xcio_configure_domain(XcIOContext *ctxt){
    int err = 0;

    if(ctxt->configure){
        err = ctxt->configure(ctxt->data, ctxt->domain, ctxt->vmconfig, ctxt->vmconfig_n);
    } else {
        err = -EINVAL;
    }
    return err;
}

static inline int xcio_read(XcIOContext *ctxt, void *buf, int n){
    int rc;

    rc = IOStream_read(ctxt->io, buf, n);
    return (rc == n ? 0 : rc);
}

static inline int xcio_write(XcIOContext *ctxt, void *buf, int n){
    int rc;

    rc = IOStream_write(ctxt->io, buf, n);
    return (rc == n ? 0 : rc);
}

static inline int xcio_flush(XcIOContext *ctxt){
    return IOStream_flush(ctxt->io);
}

extern void xcio_error(XcIOContext *ctxt, const char *msg, ...);
extern void xcio_info(XcIOContext *ctxt, const char *msg, ...);

#define xcio_perror(_ctxt, _msg...) \
xcio_error(_ctxt, "(errno %d %s)" _msg, errno, strerror(errno), ## _msg)

#endif /* ! __XC_XC_IO_H__ */



