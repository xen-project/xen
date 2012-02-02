/*
 *
 *  Authors:  Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *            George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

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
#include <libflask.h>

int flask_load(xc_interface *xc_handle, char *buf, uint32_t size)
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

int flask_context_to_sid(xc_interface *xc_handle, char *buf, uint32_t size, uint32_t *sid)
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

int flask_sid_to_context(xc_interface *xc_handle, int sid, char *buf, uint32_t size)
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

int flask_getenforce(xc_interface *xc_handle)
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

int flask_setenforce(xc_interface *xc_handle, int mode)
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

int flask_getbool_byid(xc_interface *xc_handle, int id, char *name, int *curr, int *pend)
{
    flask_op_t op;
    char buf[255];
    int rv;

    op.cmd = FLASK_GETBOOL2;
    op.buf = buf;
    op.size = 255;

    snprintf(buf, sizeof buf, "%i", id);

    rv = xc_flask_op(xc_handle, &op);

    if ( rv )
        return rv;
    
    sscanf(buf, "%i %i %s", curr, pend, name);

    return rv;
}

int flask_getbool_byname(xc_interface *xc_handle, char *name, int *curr, int *pend)
{
    flask_op_t op;
    char buf[255];
    int rv;

    op.cmd = FLASK_GETBOOL_NAMED;
    op.buf = buf;
    op.size = 255;

    strncpy(buf, name, op.size);

    rv = xc_flask_op(xc_handle, &op);

    if ( rv )
        return rv;
    
    sscanf(buf, "%i %i", curr, pend);

    return rv;
}

int flask_setbool(xc_interface *xc_handle, char *name, int value, int commit)
{
    flask_op_t op;
    char buf[255];
    int size = 255;

    op.cmd = FLASK_SETBOOL_NAMED;
    op.buf = buf;
    op.size = size;

    snprintf(buf, size, "%s %i %i", name, value, commit);

    return xc_flask_op(xc_handle, &op);
}

int flask_add_pirq(xc_interface *xc_handle, unsigned int pirq, char *scontext)
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

int flask_add_ioport(xc_interface *xc_handle, unsigned long low, unsigned long high,
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

int flask_add_iomem(xc_interface *xc_handle, unsigned long low, unsigned long high,
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

int flask_add_device(xc_interface *xc_handle, unsigned long device, char *scontext)
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

int flask_del_pirq(xc_interface *xc_handle, unsigned int pirq)
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

int flask_del_ioport(xc_interface *xc_handle, unsigned long low, unsigned long high)
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

int flask_del_iomem(xc_interface *xc_handle, unsigned long low, unsigned long high)
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

int flask_del_device(xc_interface *xc_handle, unsigned long device)
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

int flask_access(xc_interface *xc_handle, const char *scon, const char *tcon,
                u_int16_t tclass, u_int32_t req,
                u_int32_t *allowed, u_int32_t *decided,
                u_int32_t *auditallow, u_int32_t *auditdeny,
                u_int32_t *seqno)
{
/* maximum number of digits in a 16-bit decimal number: */
#define MAX_SHORT_DEC_LEN 5

    char *buf;
    int bufLen;
    int err;
    flask_op_t op;
    u_int32_t dummy_allowed;
    u_int32_t dummy_decided;
    u_int32_t dummy_auditallow;
    u_int32_t dummy_auditdeny;
    u_int32_t dummy_seqno;
  
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

int flask_avc_hashstats(xc_interface *xc_handle, char *buf, int size)
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

int flask_avc_cachestats(xc_interface *xc_handle, char *buf, int size)
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

int flask_policyvers(xc_interface *xc_handle, char *buf, int size)
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

int flask_getavc_threshold(xc_interface *xc_handle)
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

int flask_setavc_threshold(xc_interface *xc_handle, int threshold)
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
