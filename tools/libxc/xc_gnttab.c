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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_private.h"

int xc_gnttab_op(xc_interface *xch, int cmd, void * op, int op_size, int count)
{
    int ret = 0;
    DECLARE_HYPERCALL_BOUNCE(op, count * op_size, XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( xc_hypercall_bounce_pre(xch, op) )
    {
        PERROR("Could not bounce buffer for grant table op hypercall");
        goto out1;
    }

    ret = xencall3(xch->xcall,  __HYPERVISOR_grant_table_op,
                   cmd, HYPERCALL_BUFFER_AS_ARG(op), count);

    xc_hypercall_bounce_post(xch, op);

 out1:
    return ret;
}

int xc_gnttab_query_size(xc_interface *xch, struct gnttab_query_size *query)
{
    int rc;

    rc = xc_gnttab_op(xch, GNTTABOP_query_size, query, sizeof(*query), 1);

    if ( rc || (query->status != GNTST_okay) )
        ERROR("Could not query dom %u's grant size\n", query->dom);

    return rc;
}

int xc_gnttab_get_version(xc_interface *xch, uint32_t domid)
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

static void *_gnttab_map_table(xc_interface *xch, uint32_t domid, int *gnt_num)
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
        ERROR("Could not query dom%d's grant size\n", domid);
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

grant_entry_v1_t *xc_gnttab_map_table_v1(xc_interface *xch, uint32_t domid,
                                         int *gnt_num)
{
    if (xc_gnttab_get_version(xch, domid) == 2)
        return NULL;
    return _gnttab_map_table(xch, domid, gnt_num);
}

grant_entry_v2_t *xc_gnttab_map_table_v2(xc_interface *xch, uint32_t domid,
                                         int *gnt_num)
{
    if (xc_gnttab_get_version(xch, domid) != 2)
        return NULL;
    return _gnttab_map_table(xch, domid, gnt_num);
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
