/******************************************************************************
 * xc_vbd.c
 * 
 * API for manipulating and accessing per-domain virtual block devices.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#define _GNU_SOURCE
#include "xc_private.h"

int xc_vbd_create(int xc_handle,
                  unsigned int domid, 
                  unsigned short vbdid, 
                  int writeable)
{
    block_io_op_t op; 
    op.cmd = BLOCK_IO_OP_VBD_CREATE; 
    op.u.create_params.domain  = domid;
    op.u.create_params.vdevice = vbdid;
    op.u.create_params.mode    = VBD_MODE_R | (writeable ? VBD_MODE_W : 0);
    return do_block_io_op(xc_handle, &op);
}


int xc_vbd_destroy(int xc_handle,
                   unsigned int domid, 
                   unsigned short vbdid)
{
    block_io_op_t op; 
    op.cmd = BLOCK_IO_OP_VBD_DELETE; 
    op.u.delete_params.domain  = domid;
    op.u.delete_params.vdevice = vbdid;
    return do_block_io_op(xc_handle, &op);
}


int xc_vbd_grow(int xc_handle,
                unsigned int domid, 
                unsigned short vbdid,
                xc_vbdextent_t *extent)
{
    block_io_op_t op; 
    op.cmd = BLOCK_IO_OP_VBD_GROW; 
    op.u.grow_params.domain  = domid; 
    op.u.grow_params.vdevice = vbdid;
    op.u.grow_params.extent.device       = extent->real_device; 
    op.u.grow_params.extent.start_sector = extent->start_sector;
    op.u.grow_params.extent.nr_sectors   = extent->nr_sectors;
    return do_block_io_op(xc_handle, &op);
}


int xc_vbd_shrink(int xc_handle,
                  unsigned int domid, 
                  unsigned short vbdid)
{
    block_io_op_t op; 
    op.cmd = BLOCK_IO_OP_VBD_SHRINK; 
    op.u.shrink_params.domain  = domid; 
    op.u.shrink_params.vdevice = vbdid;
    return do_block_io_op(xc_handle, &op);
}


int xc_vbd_setextents(int xc_handle,
                      unsigned int domid, 
                      unsigned short vbdid,
                      unsigned int nr_extents,
                      xc_vbdextent_t *extents)
{
    int           i, rc;
    block_io_op_t op;
    xen_extent_t *real_extents = NULL;

    if ( nr_extents != 0 )
    {
        real_extents = malloc(nr_extents * sizeof(xc_vbdextent_t));
        if ( (real_extents == NULL) || 
             (mlock(real_extents, nr_extents * sizeof(xc_vbdextent_t)) != 0) )
        {
            if ( real_extents != NULL )
                free(real_extents);
            return -ENOMEM;
        }

        for ( i = 0; i < nr_extents; i++ )
        {
            real_extents[i].device       = extents[i].real_device;
            real_extents[i].start_sector = extents[i].start_sector;
            real_extents[i].nr_sectors   = extents[i].nr_sectors;
        }
    }

    op.cmd = BLOCK_IO_OP_VBD_SET_EXTENTS;
    op.u.setextents_params.domain     = domid;
    op.u.setextents_params.vdevice    = vbdid;
    op.u.setextents_params.nr_extents = nr_extents;
    op.u.setextents_params.extents    = real_extents;
    rc = do_block_io_op(xc_handle, &op);

    if ( real_extents != NULL )
    {
        (void)munlock(real_extents, nr_extents * sizeof(xc_vbdextent_t));
        free(real_extents);
    }

    return rc;
}


int xc_vbd_getextents(int xc_handle,
                      unsigned int domid, 
                      unsigned short vbdid,
                      unsigned int max_extents,
                      xc_vbdextent_t *extents,
                      int *writeable)
{
    int           i, rc;
    block_io_op_t op;
    xen_extent_t *real_extents = malloc(max_extents * sizeof(xc_vbdextent_t));

    if ( (real_extents == NULL) || 
         (mlock(real_extents, max_extents * sizeof(xc_vbdextent_t)) != 0) )
    {
        if ( real_extents != NULL )
            free(real_extents);
        return -ENOMEM;
    }

    op.cmd = BLOCK_IO_OP_VBD_INFO;
    op.u.info_params.domain     = domid;
    op.u.info_params.vdevice    = vbdid;
    op.u.info_params.maxextents = max_extents;
    op.u.info_params.extents    = real_extents;
    rc = do_block_io_op(xc_handle, &op);

    (void)munlock(real_extents, max_extents * sizeof(xc_vbdextent_t));

    if ( rc >= 0 )
    {
        for ( i = 0; i < op.u.info_params.nextents; i++ )
        {
            extents[i].real_device  = real_extents[i].device;
            extents[i].start_sector = real_extents[i].start_sector;
            extents[i].nr_sectors   = real_extents[i].nr_sectors;
        }

        if ( writeable != NULL )
            *writeable = !!(op.u.info_params.mode & VBD_MODE_W);

        rc = op.u.info_params.nextents;
    }

    free(real_extents);

    return rc;
}


int xc_vbd_probe(int xc_handle,
                 unsigned int domid,
                 unsigned int max_vbds,
                 xc_vbd_t *vbds)
{
    block_io_op_t op; 
    xen_disk_info_t *xdi = &op.u.probe_params.xdi; 
    int i, j, ret, allocsz = max_vbds * sizeof(xen_disk_t); 

    op.cmd = BLOCK_IO_OP_VBD_PROBE; 
    op.u.probe_params.domain = domid; 
    
    xdi->max   = max_vbds;
    xdi->disks = malloc(allocsz);
    xdi->count = 0;

    if ( (xdi->disks == NULL) || (mlock(xdi->disks, allocsz) != 0) )
    {
        if ( xdi->disks != NULL )
            free(xdi->disks);
        return -ENOMEM;
    }

    ret = do_block_io_op(xc_handle, &op);

    (void)munlock(xdi->disks, allocsz);

    if ( ret >= 0 )
    {
	for ( i = 0, j = 0; i < xdi->count; i++ )
        {
            if ( !(xdi->disks[i].info & XD_FLAG_VIRT) )
                continue;
            
            vbds[j].domid = xdi->disks[i].domain;
            vbds[j].vbdid = xdi->disks[i].device;
            vbds[j].flags = (xdi->disks[i].info & XD_FLAG_RO) ? 
                0 : XC_VBDF_WRITEABLE;
            vbds[j].nr_sectors = xdi->disks[i].capacity;
            
            j++;
        }

        ret = j;
    }
    
    free(xdi->disks);

    return ret;
}
