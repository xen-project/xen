/******************************************************************************
 *
 * Copyright (c) 2007-2008, D G Murray <Derek.Murray@cl.cam.ac.uk>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"

int xc_gnttab_op(xc_interface *xch, int cmd, void * op, int op_size, int count)
{
    int ret = 0;
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BOUNCE(op, count * op_size, XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( xc_hypercall_bounce_pre(xch, op) )
    {
        PERROR("Could not bounce buffer for grant table op hypercall");
        goto out1;
    }

    hypercall.op = __HYPERVISOR_grant_table_op;
    hypercall.arg[0] = cmd;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(op);
    hypercall.arg[2] = count;

    ret = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_bounce_post(xch, op);

 out1:
    return ret;
}

int xc_gnttab_get_version(xc_interface *xch, int domid)
{
    struct gnttab_get_version query;
    int rc;

    query.dom = domid;
    rc = xc_gnttab_op(xch, GNTTABOP_get_version, &query, sizeof(query),
                      1);
    if ( rc < 0 )
        return rc;
    else
        return query.version;
}

static void *_gnttab_map_table(xc_interface *xch, int domid, int *gnt_num)
{
    int rc, i;
    struct gnttab_query_size query;
    struct gnttab_setup_table setup;
    DECLARE_HYPERCALL_BUFFER(unsigned long, frame_list);
    xen_pfn_t *pfn_list = NULL;
    grant_entry_v1_t *gnt = NULL;

    if ( !gnt_num )
        return NULL;

    query.dom = domid;
    rc = xc_gnttab_op(xch, GNTTABOP_query_size, &query, sizeof(query), 1);

    if ( rc || (query.status != GNTST_okay) )
    {
        ERROR("Could not query dom's grant size\n", domid);
        return NULL;
    }

    *gnt_num = query.nr_frames * (PAGE_SIZE / sizeof(grant_entry_v1_t) );

    frame_list = xc_hypercall_buffer_alloc(xch, frame_list, query.nr_frames * sizeof(unsigned long));
    if ( !frame_list )
    {
        ERROR("Could not allocate frame_list in xc_gnttab_map_table\n");
        return NULL;
    }

    pfn_list = malloc(query.nr_frames * sizeof(xen_pfn_t));
    if ( !pfn_list )
    {
        ERROR("Could not allocate pfn_list in xc_gnttab_map_table\n");
        goto err;
    }

    setup.dom = domid;
    setup.nr_frames = query.nr_frames;
    set_xen_guest_handle(setup.frame_list, frame_list);

    /* XXX Any race with other setup_table hypercall? */
    rc = xc_gnttab_op(xch, GNTTABOP_setup_table, &setup, sizeof(setup),
                      1);

    if ( rc || (setup.status != GNTST_okay) )
    {
        ERROR("Could not get grant table frame list\n");
        goto err;
    }

    for ( i = 0; i < setup.nr_frames; i++ )
        pfn_list[i] = frame_list[i];

    gnt = xc_map_foreign_pages(xch, domid, PROT_READ, pfn_list,
                               setup.nr_frames);
    if ( !gnt )
    {
        ERROR("Could not map grant table\n");
        goto err;
    }

err:
    if ( frame_list )
        xc_hypercall_buffer_free(xch, frame_list);
    free(pfn_list);

    return gnt;
}

grant_entry_v1_t *xc_gnttab_map_table_v1(xc_interface *xch, int domid,
                                         int *gnt_num)
{
    if (xc_gnttab_get_version(xch, domid) == 2)
        return NULL;
    return _gnttab_map_table(xch, domid, gnt_num);
}

grant_entry_v2_t *xc_gnttab_map_table_v2(xc_interface *xch, int domid,
                                         int *gnt_num)
{
    if (xc_gnttab_get_version(xch, domid) != 2)
        return NULL;
    return _gnttab_map_table(xch, domid, gnt_num);
}

void *xc_gnttab_map_grant_ref(xc_gnttab *xcg,
                              uint32_t domid,
                              uint32_t ref,
                              int prot)
{
	return xcg->ops->u.gnttab.grant_map(xcg, xcg->ops_handle, 1, 0, prot,
	                                    &domid, &ref, -1, -1);
}

void *xc_gnttab_map_grant_refs(xc_gnttab *xcg,
                               uint32_t count,
                               uint32_t *domids,
                               uint32_t *refs,
                               int prot)
{
	return xcg->ops->u.gnttab.grant_map(xcg, xcg->ops_handle, count, 0,
	                                    prot, domids, refs, -1, -1);
}

void *xc_gnttab_map_domain_grant_refs(xc_gnttab *xcg,
                                      uint32_t count,
                                      uint32_t domid,
                                      uint32_t *refs,
                                      int prot)
{
	return xcg->ops->u.gnttab.grant_map(xcg, xcg->ops_handle, count,
	                                    XC_GRANT_MAP_SINGLE_DOMAIN,
	                                    prot, &domid, refs, -1, -1);
}

void *xc_gnttab_map_grant_ref_notify(xc_gnttab *xcg,
                                     uint32_t domid,
                                     uint32_t ref,
                                     int prot,
                                     uint32_t notify_offset,
                                     evtchn_port_t notify_port)
{
	return xcg->ops->u.gnttab.grant_map(xcg, xcg->ops_handle, 1, 0, prot,
	                              &domid, &ref, notify_offset, notify_port);
}


int xc_gnttab_munmap(xc_gnttab *xcg,
                     void *start_address,
                     uint32_t count)
{
	return xcg->ops->u.gnttab.munmap(xcg, xcg->ops_handle,
					 start_address, count);
}

int xc_gnttab_set_max_grants(xc_gnttab *xcg, uint32_t count)
{
	if (!xcg->ops->u.gnttab.set_max_grants)
		return 0;
	return xcg->ops->u.gnttab.set_max_grants(xcg, xcg->ops_handle, count);
}

void *xc_gntshr_share_pages(xc_gntshr *xcg, uint32_t domid,
                            int count, uint32_t *refs, int writable)
{
	return xcg->ops->u.gntshr.share_pages(xcg, xcg->ops_handle, domid,
	                                      count, refs, writable, -1, -1);
}

void *xc_gntshr_share_page_notify(xc_gntshr *xcg, uint32_t domid,
                                  uint32_t *ref, int writable,
                                  uint32_t notify_offset,
                                  evtchn_port_t notify_port)
{
	return xcg->ops->u.gntshr.share_pages(xcg, xcg->ops_handle,
			domid, 1, ref, writable, notify_offset, notify_port);
}

/*
 * Unmaps the @count pages starting at @start_address, which were mapped by a
 * call to xc_gntshr_share_*. Never logs.
 */
int xc_gntshr_munmap(xc_gntshr *xcg, void *start_address, uint32_t count)
{
	return xcg->ops->u.gntshr.munmap(xcg, xcg->ops_handle,
					 start_address, count);
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
