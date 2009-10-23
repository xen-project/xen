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
