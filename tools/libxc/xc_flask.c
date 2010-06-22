/******************************************************************************
 * xc_flask.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include "xc_private.h"
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define OCON_PIRQ_STR   "pirq"
#define OCON_IOPORT_STR "ioport"
#define OCON_IOMEM_STR  "iomem"
#define OCON_DEVICE_STR "pcidevice"
#define INITCONTEXTLEN  256

int xc_flask_op(xc_interface *xch, flask_op_t *op)
{
    int ret = -1;
    DECLARE_HYPERCALL;

    hypercall.op     = __HYPERVISOR_xsm_op;
    hypercall.arg[0] = (unsigned long)op;

    if ( mlock(op, sizeof(*op)) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out;
    }

    if ( (ret = do_xen_hypercall(xch, &hypercall)) < 0 )
    {
        if ( errno == EACCES )
            fprintf(stderr, "XSM operation failed!\n");
    }

    safe_munlock(op, sizeof(*op));

 out:
    return ret;
}

int xc_flask_load(xc_interface *xc_handle, char *buf, uint32_t size)
{
    int err;
    flask_op_t op;
    
    op.cmd = FLASK_LOAD;
    op.buf = buf;
    op.size = size;
    
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;

    return 0;
}

int xc_flask_context_to_sid(xc_interface *xc_handle, char *buf, uint32_t size, uint32_t *sid)
{
    int err;
    flask_op_t op;
    
    op.cmd = FLASK_CONTEXT_TO_SID;
    op.buf = buf;
    op.size = size;
    
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;
    
    sscanf(buf, "%u", sid);

    return 0;
}

int xc_flask_sid_to_context(xc_interface *xc_handle, int sid, char *buf, uint32_t size)
{
    int err;
    flask_op_t op;
    
    op.cmd = FLASK_SID_TO_CONTEXT;
    op.buf = buf;
    op.size = size;
    
    snprintf(buf, size, "%u", sid);

    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;

    return 0;
}

int xc_flask_getenforce(xc_interface *xc_handle)
{
    int err;
    flask_op_t op;
    char buf[20];            
    int size = 20;
    int mode;
 
    op.cmd = FLASK_GETENFORCE;
    op.buf = buf;
    op.size = size;
    
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;

    sscanf(buf, "%i", &mode);

    return mode;
}

int xc_flask_setenforce(xc_interface *xc_handle, int mode)
{
    int err;
    flask_op_t op;
    char buf[20];
    int size = 20; 
 
    op.cmd = FLASK_SETENFORCE;
    op.buf = buf;
    op.size = size;
   
    snprintf(buf, size, "%i", mode);
 
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;

    return 0;
}

int xc_flask_add_pirq(xc_interface *xc_handle, unsigned int pirq, char *scontext)
{
    int err;
    flask_op_t op;
    char *buf;
    char *pirq_s = OCON_PIRQ_STR;
    int size = INITCONTEXTLEN + strlen(pirq_s) + (sizeof(unsigned int)) +
                (sizeof(char) * 3);

    if ( (buf = (char *) malloc(size)) == NULL )
        return -ENOMEM;
    memset(buf, 0, size);

    op.cmd = FLASK_ADD_OCONTEXT;
    snprintf(buf, size, "%s %255s %u", pirq_s, scontext, pirq);
    op.buf = buf;
    op.size = size;

    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    free(buf);
    return 0;

}

int xc_flask_add_ioport(xc_interface *xc_handle, unsigned long low, unsigned long high,
                      char *scontext)
{
    int err;
    flask_op_t op;
    char *buf;
    char *ioport = OCON_IOPORT_STR;
    int size = INITCONTEXTLEN + strlen(ioport) +
                (sizeof(unsigned long) * 2) + (sizeof(char) * 4);

    if ( (buf = (char *) malloc(size)) == NULL )
        return -ENOMEM;
    memset(buf, 0, size);

    op.cmd = FLASK_ADD_OCONTEXT;
    snprintf(buf, size, "%s %255s %lu %lu", ioport, scontext, low, high);
    op.buf = buf;
    op.size = size;

    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    free(buf);
    return 0;

}

int xc_flask_add_iomem(xc_interface *xc_handle, unsigned long low, unsigned long high,
                     char *scontext)
{
    int err;
    flask_op_t op;
    char *buf;
    char *iomem = OCON_IOMEM_STR;
    int size = INITCONTEXTLEN + strlen(iomem) +
                (sizeof(unsigned long) * 2) + (sizeof(char) * 4);

    if ( (buf = (char *) malloc(size)) == NULL )
        return -ENOMEM;
    memset(buf, 0, size);

    op.cmd = FLASK_ADD_OCONTEXT;
    snprintf(buf, size, "%s %255s %lu %lu", iomem, scontext, low, high);
    op.buf = buf;
    op.size = size;

    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    free(buf);
    return 0;

}

int xc_flask_add_device(xc_interface *xc_handle, unsigned long device, char *scontext)
{
    int err;
    flask_op_t op;
    char *buf;
    char *dev = OCON_DEVICE_STR;
    int size = INITCONTEXTLEN + strlen(dev) + (sizeof(unsigned long)) +
                (sizeof(char) * 3);

    if ( (buf = (char *) malloc(size)) == NULL )
        return -ENOMEM;
    memset(buf, 0, size);

    op.cmd = FLASK_ADD_OCONTEXT;
    snprintf(buf, size, "%s %255s %lu", dev, scontext, device);
    op.buf = buf;
    op.size = size;

    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    free(buf);
    return 0;

}

int xc_flask_del_pirq(xc_interface *xc_handle, unsigned int pirq)
{
    int err;
    flask_op_t op;
    char *buf;
    char *pirq_s = OCON_PIRQ_STR;
    int size = strlen(pirq_s) + (sizeof(unsigned int)) +
                (sizeof(char) * 2);

    if ( (buf = (char *) malloc(size)) == NULL )
        return -ENOMEM;
    memset(buf, 0, size);

    op.cmd = FLASK_DEL_OCONTEXT;
    snprintf(buf, size, "%s %u", pirq_s, pirq);
    op.buf = buf;
    op.size = size;

    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    free(buf);
    return 0;

}

int xc_flask_del_ioport(xc_interface *xc_handle, unsigned long low, unsigned long high)
{
    int err;
    flask_op_t op;
    char *buf;
    char *ioport = OCON_IOPORT_STR;
    int size = strlen(ioport) + (sizeof(unsigned long) * 2) +
                (sizeof(char) * 3);

    if ( (buf = (char *) malloc(size)) == NULL )
        return -ENOMEM;
    memset(buf, 0, size);

    op.cmd = FLASK_DEL_OCONTEXT;
    snprintf(buf, size, "%s %lu %lu", ioport, low, high);
    op.buf = buf;
    op.size = size;

    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    free(buf);
    return 0;

}

int xc_flask_del_iomem(xc_interface *xc_handle, unsigned long low, unsigned long high)
{
    int err;
    flask_op_t op;
    char *buf;
    char *iomem = OCON_IOMEM_STR;
    int size = strlen(iomem) + (sizeof(unsigned long) * 2) +
                (sizeof(char) * 3);

    if ( (buf = (char *) malloc(size)) == NULL )
        return -ENOMEM;
    memset(buf, 0, size);

    op.cmd = FLASK_DEL_OCONTEXT;
    snprintf(buf, size, "%s %lu %lu", iomem, low, high);
    op.buf = buf;
    op.size = size;

    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    free(buf);
    return 0;

}

int xc_flask_del_device(xc_interface *xc_handle, unsigned long device)
{
    int err;
    flask_op_t op;
    char *buf;
    char *dev = OCON_DEVICE_STR;
    int size = strlen(dev) + (sizeof(unsigned long)) + (sizeof(char) * 2);

    if ( (buf = (char *) malloc(size)) == NULL )
        return -ENOMEM;
    memset(buf, 0, size);

    op.cmd = FLASK_DEL_OCONTEXT;
    snprintf(buf, size, "%s %lu", dev, device);
    op.buf = buf;
    op.size = size;

    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    free(buf);
    return 0;

}

int xc_flask_access(xc_interface *xc_handle, const char *scon, const char *tcon,
                uint16_t tclass, uint32_t req,
                uint32_t *allowed, uint32_t *decided,
                uint32_t *auditallow, uint32_t *auditdeny,
                uint32_t *seqno)
{
/* maximum number of digits in a 16-bit decimal number: */
#define MAX_SHORT_DEC_LEN 5

    char *buf;
    int bufLen;
    int err;
    flask_op_t op;
    uint32_t dummy_allowed;
    uint32_t dummy_decided;
    uint32_t dummy_auditallow;
    uint32_t dummy_auditdeny;
    uint32_t dummy_seqno;
  
    if (!allowed)
        allowed = &dummy_allowed;
    if (!decided)
        decided = &dummy_decided;
    if (!auditallow)
        auditallow = &dummy_auditallow;
    if (!auditdeny)
        auditdeny = &dummy_auditdeny;
    if (!seqno)
        seqno = &dummy_seqno;

    if (!scon)
        return -EINVAL;
    if (!tcon)
        return -EINVAL;

    bufLen = strlen(scon) + 1 + strlen(tcon) + 1 +
        MAX_SHORT_DEC_LEN + 1 +
        sizeof(req)*2 + 1;
    buf = malloc(bufLen);
    snprintf(buf, bufLen, "%s %s %hu %x", scon, tcon, tclass, req);

    op.cmd = FLASK_ACCESS;
    op.buf = buf;
    op.size = strlen(buf)+1;
    
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }
   
    if (sscanf(op.buf, "%x %x %x %x %u",
               allowed, decided,
               auditallow, auditdeny,
               seqno) != 5) {
        err = -EILSEQ;
    }

    err = ((*allowed & req) == req)? 0 : -EPERM;

    return err;

}

int xc_flask_avc_hashstats(xc_interface *xc_handle, char *buf, int size)
{
    int err;
    flask_op_t op;
  
    op.cmd = FLASK_AVC_HASHSTATS;
    op.buf = buf;
    op.size = size;
  
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    return 0;
}

int xc_flask_avc_cachestats(xc_interface *xc_handle, char *buf, int size)
{
    int err;
    flask_op_t op;
  
    op.cmd = FLASK_AVC_CACHESTATS;
    op.buf = buf;
    op.size = size;
  
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    return 0;
}

int xc_flask_policyvers(xc_interface *xc_handle, char *buf, int size)
{
    int err;
    flask_op_t op;
  
    op.cmd = FLASK_POLICYVERS;
    op.buf = buf;
    op.size = size;

    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
    {
        free(buf);
        return err;
    }

    return 0;
}

int xc_flask_getavc_threshold(xc_interface *xc_handle)
{
    int err;
    flask_op_t op;
    char buf[20];            
    int size = 20;
    int threshold;
 
    op.cmd = FLASK_GETAVC_THRESHOLD;
    op.buf = buf;
    op.size = size;
    
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;

    sscanf(buf, "%i", &threshold);

    return threshold;
}

int xc_flask_setavc_threshold(xc_interface *xc_handle, int threshold)
{
    int err;
    flask_op_t op;
    char buf[20];            
    int size = 20;
 
    op.cmd = FLASK_SETAVC_THRESHOLD;
    op.buf = buf;
    op.size = size;

    snprintf(buf, size, "%i", threshold);
 
    if ( (err = xc_flask_op(xc_handle, &op)) != 0 )
        return err;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
