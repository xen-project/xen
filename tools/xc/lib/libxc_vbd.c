/******************************************************************************
 * libxc_vbd.c
 * 
 * API for manipulating and accessing per-domain virtual block devices.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#define _GNU_SOURCE
#include "libxc_private.h"

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


int xc_vbd_add_extent(int xc_handle,
                      unsigned int domid, 
                      unsigned short vbdid,
                      unsigned short real_device,
                      unsigned long start_sector,
                      unsigned long nr_sectors)
{
    block_io_op_t op; 
    op.cmd = BLOCK_IO_OP_VBD_ADD; 
    op.u.add_params.domain  = domid; 
    op.u.add_params.vdevice = vbdid;
    op.u.add_params.extent.device       = real_device; 
    op.u.add_params.extent.start_sector = start_sector;
    op.u.add_params.extent.nr_sectors   = nr_sectors;
    return do_block_io_op(xc_handle, &op);
}


int xc_vbd_delete_extent(int xc_handle,
                         unsigned int domid, 
                         unsigned short vbdid,
                         unsigned short real_device,
                         unsigned long start_sector,
                         unsigned long nr_sectors)
{
    block_io_op_t op; 
    op.cmd = BLOCK_IO_OP_VBD_REMOVE; 
    op.u.add_params.domain  = domid; 
    op.u.add_params.vdevice = vbdid;
    op.u.add_params.extent.device       = real_device; 
    op.u.add_params.extent.start_sector = start_sector;
    op.u.add_params.extent.nr_sectors   = nr_sectors;
    return do_block_io_op(xc_handle, &op);
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
