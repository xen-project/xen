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
do_gnttab_op( int xc_handle,
              unsigned long cmd,
              gnttab_op_t *op,
              unsigned long count )
{
    int ret = -1;
    privcmd_hypercall_t hypercall;

    hypercall.op     = __HYPERVISOR_grant_table_op;
    hypercall.arg[0] = cmd;
    hypercall.arg[1] = (unsigned long)(op);
    hypercall.arg[2] = count;

    if ( mlock(op, sizeof(*op)) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out1;
    }

    if ( (ret = do_xen_hypercall(xc_handle, &hypercall)) < 0 )
    {
        printf("do_gnttab_op: hypercall returned error %d\n", ret);
        goto out2;
    }

 out2: (void)munlock(op, sizeof(*op));
 out1: return ret;
}


int xc_gnttab_map_grant_ref(int         xc_handle,
                            memory_t    host_virt_addr,
                            u32         dom,
                            u16         ref,
                            u16         flags,
                            s16        *handle,
                            memory_t   *dev_bus_addr)
{
    gnttab_op_t     op;
    int             rc;

    op.u.map_grant_ref.host_virt_addr = host_virt_addr;
    op.u.map_grant_ref.dom            = (domid_t)dom;
    op.u.map_grant_ref.ref            = ref;
    op.u.map_grant_ref.flags          = flags;
 
    if ( (rc = do_gnttab_op(xc_handle, GNTTABOP_map_grant_ref, &op, 1)) == 0 )
    {
        *handle         = op.u.map_grant_ref.handle;
        *dev_bus_addr   = op.u.map_grant_ref.dev_bus_addr;
    }

    return rc;
}


int xc_gnttab_unmap_grant_ref(int       xc_handle,
                              memory_t  host_virt_addr,
                              memory_t  dev_bus_addr,
                              u16       handle,
                              s16      *status)
{
    gnttab_op_t     op;
    int             rc;

    op.u.unmap_grant_ref.host_virt_addr = host_virt_addr;
    op.u.unmap_grant_ref.dev_bus_addr   = dev_bus_addr;
    op.u.unmap_grant_ref.handle         = handle;
 
    if ( (rc = do_gnttab_op(xc_handle, GNTTABOP_unmap_grant_ref, &op, 1)) == 0 )
        *status = op.u.unmap_grant_ref.status;

    return rc;
}

int xc_gnttab_setup_table(int        xc_handle,
                          u32        dom,
                          u16        nr_frames,
                          s16       *status,
                          memory_t **frame_list)
{
    gnttab_op_t     op;
    int             rc;
    int             i;

    op.u.setup_table.dom        = (domid_t)dom;
    op.u.setup_table.nr_frames  = nr_frames;
 
    if ( (rc = do_gnttab_op(xc_handle, GNTTABOP_setup_table, &op, 1)) == 0 )
    {
        *status = op.u.setup_table.status;
        for ( i = 0; i < nr_frames; i++ )
        {
            (*frame_list)[i] = op.u.setup_table.frame_list[i];
        }
    }

    return rc;
}

int xc_gnttab_dump_table(int        xc_handle,
                         u32        dom,
                         s16       *status)
{
    gnttab_op_t     op;
    int             rc;

    op.u.dump_table.dom = (domid_t)dom;
 
    printf("xc_gnttab_dump_table: domain %d\n", dom);

    if ( (rc = do_gnttab_op(xc_handle, GNTTABOP_dump_table, &op, 1)) == 0 )
        *status = op.u.dump_table.status;

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
