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
#include <flask.h>
#include <xenctrl.h>

int flask_load(int xc_handle, char *buf, uint32_t size)
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

int flask_context_to_sid(int xc_handle, char *buf, uint32_t size, uint32_t *sid)
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

int flask_sid_to_context(int xc_handle, int sid, char *buf, uint32_t size)
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

int flask_getenforce(int xc_handle)
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

int flask_setenforce(int xc_handle, int mode)
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

int flask_add_pirq(int xc_handle, unsigned int pirq, char *scontext)
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

int flask_add_ioport(int xc_handle, unsigned long low, unsigned long high,
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
    snprintf(buf, size, "%s %255s %li %li", ioport, scontext, low, high);
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

int flask_add_iomem(int xc_handle, unsigned long low, unsigned long high,
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
    snprintf(buf, size, "%s %255s %li %li", iomem, scontext, low, high);
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

int flask_add_device(int xc_handle, unsigned long device, char *scontext)
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
    snprintf(buf, size, "%s %255s %li", dev, scontext, device);
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

int flask_del_pirq(int xc_handle, unsigned int pirq)
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

int flask_del_ioport(int xc_handle, unsigned long low, unsigned long high)
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
    snprintf(buf, size, "%s %li %li", ioport, low, high);
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

int flask_del_iomem(int xc_handle, unsigned long low, unsigned long high)
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
    snprintf(buf, size, "%s %li %li", iomem, low, high);
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

int flask_del_device(int xc_handle, unsigned long device)
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
    snprintf(buf, size, "%s %li", dev, device);
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
