/******************************************************************************
 * xc_gnttab.c
 * 
 * API for manipulating and accessing grant tables
 * 
 * Copyright (c) 2005 Christopher Clark
 * based on xc_evtchn.c Copyright (c) 2004, K A Fraser.
 */

#include "xc_private.h"
#include "xen/grant_table.h"

static int
do_gnttab_op(int xc_handle,
             unsigned long cmd,
             void *op,
             unsigned long count)
{
    int ret = -1;
    DECLARE_HYPERCALL;

    hypercall.op     = __HYPERVISOR_grant_table_op;
    hypercall.arg[0] = cmd;
    hypercall.arg[1] = (unsigned long)op;
    hypercall.arg[2] = count;

    if ( mlock(op, 64) )
    {
        PERROR("do_gnttab_op: op mlock failed");
        goto out;
    }

    if ( (ret = do_xen_hypercall(xc_handle, &hypercall)) < 0 )
        ERROR("do_gnttab_op: HYPERVISOR_grant_table_op failed: %d", ret);

    safe_munlock(op, 64);
 out:
    return ret;
}


int xc_gnttab_map_grant_ref(int         xc_handle,
                            uint64_t    host_virt_addr,
                            uint32_t    dom,
                            grant_ref_t ref,
                            uint16_t    flags,
                            int16_t    *status,
                            grant_handle_t *handle,
                            uint64_t   *dev_bus_addr)
{
    struct gnttab_map_grant_ref op;
    int rc;

    op.host_addr      = host_virt_addr;
    op.dom            = (domid_t)dom;
    op.ref            = ref;
    op.flags          = flags;
 
    if ( (rc = do_gnttab_op(xc_handle, GNTTABOP_map_grant_ref,
                            &op, 1)) == 0 )
    {
        *status         = op.status;
        *handle         = op.handle;
        *dev_bus_addr   = op.dev_bus_addr;
    }

    return rc;
}


int xc_gnttab_unmap_grant_ref(int       xc_handle,
                              uint64_t  host_virt_addr,
                              uint64_t  dev_bus_addr,
                              grant_handle_t handle,
                              int16_t  *status)
{
    struct gnttab_unmap_grant_ref op;
    int rc;

    op.host_addr      = host_virt_addr;
    op.dev_bus_addr   = dev_bus_addr;
    op.handle         = handle;
 
    if ( (rc = do_gnttab_op(xc_handle, GNTTABOP_unmap_grant_ref,
                            &op, 1)) == 0 )
    {
        *status = op.status;
    }

    return rc;
}

int xc_gnttab_setup_table(int        xc_handle,
                          uint32_t   dom,
                          uint16_t   nr_frames,
                          int16_t   *status,
                          unsigned long **frame_list)
{
    struct gnttab_setup_table op;
    int rc, i;

    op.dom       = (domid_t)dom;
    op.nr_frames = nr_frames;
 
    if ( (rc = do_gnttab_op(xc_handle, GNTTABOP_setup_table, &op, 1)) == 0 )
    {
        *status = op.status;
        for ( i = 0; i < nr_frames; i++ )
            (*frame_list)[i] = op.frame_list[i];
    }

    return rc;
}

int xc_gnttab_dump_table(int        xc_handle,
                         uint32_t   dom,
                         int16_t   *status)
{
    struct gnttab_dump_table op;
    int rc;

    op.dom = (domid_t)dom;

    if ( (rc = do_gnttab_op(xc_handle, GNTTABOP_dump_table, &op, 1)) == 0 )
        *status = op.status;

    return rc;
}

int xc_grant_interface_open(void)
{
    int fd = open("/proc/xen/grant", O_RDWR);
    if ( fd == -1 )
        PERROR("Could not obtain handle on grant command interface");
    return fd;

}

int xc_grant_interface_close(int xc_grant_handle)
{
    return close(xc_grant_handle);
}
