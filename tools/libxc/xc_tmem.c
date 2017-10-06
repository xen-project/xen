/******************************************************************************
 * xc_tmem.c
 *
 * Copyright (C) 2008 Oracle Corp.
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
#include <inttypes.h>
#include <assert.h>
#include <xen/tmem.h>

int xc_tmem_control(xc_interface *xch,
                    int32_t pool_id,
                    uint32_t cmd,
                    uint32_t cli_id,
                    uint32_t len,
                    uint32_t arg,
                    void *buf)
{
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(buf, len, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int rc;

    sysctl.cmd = XEN_SYSCTL_tmem_op;
    sysctl.u.tmem_op.pool_id = pool_id;
    sysctl.u.tmem_op.cmd = cmd;
    sysctl.u.tmem_op.cli_id = cli_id;
    sysctl.u.tmem_op.len = len;
    sysctl.u.tmem_op.arg = arg;
    sysctl.u.tmem_op.pad = 0;
    sysctl.u.tmem_op.oid.oid[0] = 0;
    sysctl.u.tmem_op.oid.oid[1] = 0;
    sysctl.u.tmem_op.oid.oid[2] = 0;

    if ( cmd == XEN_SYSCTL_TMEM_OP_SET_CLIENT_INFO ||
         cmd == XEN_SYSCTL_TMEM_OP_SET_AUTH )
        HYPERCALL_BOUNCE_SET_DIR(buf, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    if ( len )
    {
        if ( buf == NULL )
        {
            errno = EINVAL;
            return -1;
        }
        if ( xc_hypercall_bounce_pre(xch, buf) )
        {
            PERROR("Could not bounce buffer for tmem control hypercall");
            return -1;
        }
    }

    set_xen_guest_handle(sysctl.u.tmem_op.u.buf, buf);

    rc = do_sysctl(xch, &sysctl);

    if ( len )
        xc_hypercall_bounce_post(xch, buf);

    return rc;
}

int xc_tmem_control_oid(xc_interface *xch,
                        int32_t pool_id,
                        uint32_t cmd,
                        uint32_t cli_id,
                        uint32_t len,
                        uint32_t arg,
                        struct xen_tmem_oid oid,
                        void *buf)
{
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(buf, len, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int rc;

    sysctl.cmd = XEN_SYSCTL_tmem_op;
    sysctl.u.tmem_op.pool_id = pool_id;
    sysctl.u.tmem_op.cmd = cmd;
    sysctl.u.tmem_op.cli_id = cli_id;
    sysctl.u.tmem_op.len = len;
    sysctl.u.tmem_op.arg = arg;
    sysctl.u.tmem_op.pad = 0;
    sysctl.u.tmem_op.oid = oid;

    if ( len  )
    {
        if ( buf == NULL )
        {
            errno = EINVAL;
            return -1;
        }
        if ( xc_hypercall_bounce_pre(xch, buf) )
        {
            PERROR("Could not bounce buffer for tmem control (OID) hypercall");
            return -1;
        }
    }

    set_xen_guest_handle(sysctl.u.tmem_op.u.buf, buf);

    rc = do_sysctl(xch, &sysctl);

    if ( len )
        xc_hypercall_bounce_post(xch, buf);

    return rc;
}

static int xc_tmem_uuid_parse(char *uuid_str, uint64_t *uuid_lo, uint64_t *uuid_hi)
{
    char *p = uuid_str;
    uint64_t *x = uuid_hi;
    int i = 0, digit;

    *uuid_lo = 0; *uuid_hi = 0;
    for ( p = uuid_str, i = 0; i != 36 && *p != '\0'; p++, i++ )
    {
        if ( (i == 8 || i == 13 || i == 18 || i == 23) )
        {
            if ( *p != '-' )
                return -1;
            if ( i == 18 )
                x = uuid_lo;
            continue;
        }
        else if ( *p >= '0' && *p <= '9' )
            digit = *p - '0';
        else if ( *p >= 'A' && *p <= 'F' )
            digit = *p - 'A' + 10;
        else if ( *p >= 'a' && *p <= 'f' )
            digit = *p - 'a' + 10;
        else
            return -1;
        *x = (*x << 4) | digit;
    }
    if ( (i != 1 && i != 36) || *p != '\0' )
        return -1;
    return 0;
}

int xc_tmem_auth(xc_interface *xch,
                 int cli_id,
                 char *uuid_str,
                 int enable)
{
    xen_tmem_pool_info_t pool = {
        .flags.u.auth = enable,
        .id = 0,
        .n_pages = 0,
        .uuid[0] = 0,
        .uuid[1] = 0,
    };
    if ( xc_tmem_uuid_parse(uuid_str, &pool.uuid[0],
                                      &pool.uuid[1]) < 0 )
    {
        PERROR("Can't parse uuid, use xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx");
        return -1;
    }
    return xc_tmem_control(xch, 0 /* pool_id */,
                           XEN_SYSCTL_TMEM_OP_SET_AUTH,
                           cli_id, sizeof(pool),
                           0 /* arg */, &pool);
}

/* Save/restore/live migrate */

/*
   Note that live migration complicates the save/restore format in
   multiple ways: Though saving/migration can only occur when all
   tmem pools belonging to the domain-being-saved are frozen and
   this ensures that new pools can't be created or existing pools
   grown (in number of pages), it is possible during a live migration
   that pools may be destroyed and pages invalidated while the migration
   is in process.  As a result, (1) it is not safe to pre-specify counts
   for these values precisely, but only as a "max", and (2) a "invalidation"
   list (of pools, objects, pages) must be appended when the domain is truly
   suspended.
 */

/* returns 0 if nothing to save, -1 if error saving, 1 if saved successfully */
int xc_tmem_save(xc_interface *xch,
                 uint32_t domid, int io_fd, int live, int field_marker)
{
    int marker = field_marker;
    int i, j, rc;
    uint32_t minusone = -1;
    struct tmem_handle *h;
    xen_tmem_client_t info;
    xen_tmem_pool_info_t *pools;
    char *buf = NULL;

    rc = xc_tmem_control(xch, 0, XEN_SYSCTL_TMEM_OP_SAVE_BEGIN,
                         domid, 0 /* len*/ , live, NULL);
    if ( rc )
    {
        /* Nothing to save - no tmem enabled. */
        if ( errno == ENOENT )
            return 0;

        return rc;
    }

    if ( xc_tmem_control(xch, 0 /* pool_id */,
                         XEN_SYSCTL_TMEM_OP_GET_CLIENT_INFO,
                         domid /* cli_id */, sizeof(info), 0 /* arg */,
                         &info) < 0 )
        return -1;

    /* Nothing to do. */
    if ( !info.nr_pools )
        return 0;

    pools = calloc(info.nr_pools, sizeof(*pools));
    if ( !pools )
        return -1;

    rc = xc_tmem_control(xch, 0 /* pool_id is ignored. */,
                         XEN_SYSCTL_TMEM_OP_GET_POOLS,
                         domid /* cli_id */, sizeof(*pools) * info.nr_pools,
                         0 /* arg */, pools);

    if ( rc < 0 || (uint32_t)rc > info.nr_pools )
        goto out_memory;

    /* Update it - as we have less pools between the two hypercalls. */
    info.nr_pools = (uint32_t)rc;

    if ( write_exact(io_fd, &marker, sizeof(marker)) )
        goto out_memory;

    if ( write_exact(io_fd, &info, sizeof(info)) )
        goto out_memory;

    if ( write_exact(io_fd, &minusone, sizeof(minusone)) )
        goto out_memory;

    for ( i = 0; i < info.nr_pools; i++ )
    {
        uint32_t pagesize;
        int bufsize = 0;
        int checksum = 0;
        xen_tmem_pool_info_t *pool = &pools[i];

        if ( pool->flags.raw != -1 )
        {
            if ( !pool->flags.u.persist )
                pool->n_pages = 0;

            if ( write_exact(io_fd, pool, sizeof(*pool)) )
                goto out_memory;

            if ( !pool->flags.u.persist )
                continue;

            pagesize = 1 << (pool->flags.u.pagebits + 12);
            if ( pagesize > bufsize )
            {
                bufsize = pagesize + sizeof(struct tmem_handle);
                if ( (buf = realloc(buf,bufsize)) == NULL )
                    goto out_memory;
            }
            for ( j = pool->n_pages; j > 0; j-- )
            {
                int ret;
                if ( (ret = xc_tmem_control(
                          xch, pool->id, XEN_SYSCTL_TMEM_OP_SAVE_GET_NEXT_PAGE,
                          domid, bufsize, 0, buf)) > 0 )
                {
                    h = (struct tmem_handle *)buf;
                    if ( write_exact(io_fd, &h->oid, sizeof(h->oid)) )
                        goto out_memory;

                    if ( write_exact(io_fd, &h->index, sizeof(h->index)) )
                        goto out_memory;
                    h++;
                    checksum += *(char *)h;
                    if ( write_exact(io_fd, h, pagesize) )
                        goto out_memory;
                } else if ( ret == 0 ) {
                    continue;
                } else {
                    /* page list terminator */
                    h = (struct tmem_handle *)buf;
                    h->oid.oid[0] = h->oid.oid[1] = h->oid.oid[2] = -1L;
                    if ( write_exact(io_fd, &h->oid, sizeof(h->oid)) )
                    {
 out_memory:
                        free(pools);
                        free(buf);
                        return -1;
                    }
                    break;
                }
            }
            DPRINTF("saved %"PRId64" tmem pages for dom=%d pool=%d, checksum=%x\n",
                    pool->n_pages - j, domid, pool->id, checksum);
        }
    }
    free(pools);
    free(buf);

    /* pool list terminator */
    minusone = -1;
    if ( write_exact(io_fd, &minusone, sizeof(minusone)) )
        return -1;

    return 1;
}

/* only called for live migration */
int xc_tmem_save_extra(xc_interface *xch, uint32_t domid, int io_fd, int field_marker)
{
    struct tmem_handle handle;
    int marker = field_marker;
    uint32_t minusone;
    int count = 0, checksum = 0;

    if ( write_exact(io_fd, &marker, sizeof(marker)) )
        return -1;
    while ( xc_tmem_control(xch, 0, XEN_SYSCTL_TMEM_OP_SAVE_GET_NEXT_INV, domid,
                            sizeof(handle),0,&handle) > 0 ) {
        if ( write_exact(io_fd, &handle.pool_id, sizeof(handle.pool_id)) )
            return -1;
        if ( write_exact(io_fd, &handle.oid, sizeof(handle.oid)) )
            return -1;
        if ( write_exact(io_fd, &handle.index, sizeof(handle.index)) )
            return -1;
        count++;
        checksum += handle.pool_id + handle.oid.oid[0] + handle.oid.oid[1] +
                    handle.oid.oid[2] + handle.index;
    }
    if ( count )
            DPRINTF("needed %d tmem invalidates, check=%d\n",count,checksum);
    minusone = -1;
    if ( write_exact(io_fd, &minusone, sizeof(minusone)) )
        return -1;
    return 0;
}

/* only called for live migration */
void xc_tmem_save_done(xc_interface *xch, uint32_t domid)
{
    xc_tmem_control(xch, 0, XEN_SYSCTL_TMEM_OP_SAVE_END, domid, 0, 0, NULL);
}

/* restore routines */

static int xc_tmem_restore_new_pool(
                    xc_interface *xch,
                    int cli_id,
                    uint32_t pool_id,
                    uint32_t flags,
                    uint64_t uuid_lo,
                    uint64_t uuid_hi)
{
    xen_tmem_pool_info_t pool = {
        .flags.raw = flags,
        .id = pool_id,
        .n_pages = 0,
        .uuid[0] = uuid_lo,
        .uuid[1] = uuid_hi,
    };

    return xc_tmem_control(xch, pool_id,
                           XEN_SYSCTL_TMEM_OP_SET_POOLS,
                           cli_id, sizeof(pool),
                           0 /* arg */, &pool);
}

int xc_tmem_restore(xc_interface *xch, uint32_t domid, int io_fd)
{
    uint32_t minusone;
    xen_tmem_client_t info;
    int checksum = 0;
    unsigned int i;
    char *buf = NULL;

    if ( read_exact(io_fd, &info, sizeof(info)) )
        return -1;

    /* We would never save if there weren't any pools! */
    if ( !info.nr_pools )
        return -1;

    if ( xc_tmem_control(xch, 0, XEN_SYSCTL_TMEM_OP_RESTORE_BEGIN, domid, 0, 0, NULL) < 0 )
        return -1;

    if ( xc_tmem_control(xch, 0 /* pool_id */,
                         XEN_SYSCTL_TMEM_OP_SET_CLIENT_INFO,
                         domid /* cli_id */, sizeof(info), 0 /* arg */,
                         &info) < 0 )
        return -1;

    if ( read_exact(io_fd, &minusone, sizeof(minusone)) )
        return -1;

    for ( i = 0; i < info.nr_pools; i++ )
    {
        int bufsize = 0, pagesize;
        int j;
        xen_tmem_pool_info_t pool;

        if ( read_exact(io_fd, &pool, sizeof(pool)) )
            goto out_memory;

        if ( xc_tmem_restore_new_pool(xch, domid, pool.id, pool.flags.raw,
                                      pool.uuid[0], pool.uuid[1]) < 0 )
            goto out_memory;

        if ( pool.n_pages <= 0 )
            continue;

        pagesize = 1 << (pool.flags.u.pagebits + 12);
        if ( pagesize > bufsize )
        {
            bufsize = pagesize;
            if ( (buf = realloc(buf,bufsize)) == NULL )
                goto out_memory;
        }
        for ( j = pool.n_pages; j > 0; j-- )
        {
            struct xen_tmem_oid oid;
            uint32_t index;
            int rc;

            if ( read_exact(io_fd, &oid, sizeof(oid)) )
                goto out_memory;

            if ( oid.oid[0] == -1L && oid.oid[1] == -1L && oid.oid[2] == -1L )
                break;
            if ( read_exact(io_fd, &index, sizeof(index)) )
                goto out_memory;

            if ( read_exact(io_fd, buf, pagesize) )
                goto out_memory;

            checksum += *buf;
            if ( (rc = xc_tmem_control_oid(
                      xch, pool.id, XEN_SYSCTL_TMEM_OP_RESTORE_PUT_PAGE,
                      domid, bufsize, index, oid, buf)) <= 0 )
            {
                DPRINTF("xc_tmem_restore: putting page failed, rc=%d\n",rc);
 out_memory:
                free(buf);
                return -1;
            }
        }
        if ( pool.n_pages )
            DPRINTF("restored %"PRId64" tmem pages for dom=%d pool=%d, check=%x\n",
                    pool.n_pages - j, domid, pool.id, checksum);
    }
    free(buf);

    return 0;
}

/* only called for live migration, must be called after suspend */
int xc_tmem_restore_extra(xc_interface *xch, uint32_t domid, int io_fd)
{
    uint32_t pool_id;
    struct xen_tmem_oid oid;
    uint32_t index;
    int count = 0;
    int checksum = 0;

    while ( read_exact(io_fd, &pool_id, sizeof(pool_id)) == 0 && pool_id != -1 )
    {
        if ( read_exact(io_fd, &oid, sizeof(oid)) )
            return -1;
        if ( read_exact(io_fd, &index, sizeof(index)) )
            return -1;
        if ( xc_tmem_control_oid(
                 xch, pool_id, XEN_SYSCTL_TMEM_OP_RESTORE_FLUSH_PAGE,
                 domid, 0, index, oid, NULL) <= 0 )
            return -1;
        count++;
        checksum += pool_id + oid.oid[0] + oid.oid[1] + oid.oid[2] + index;
    }
    if ( pool_id != -1 )
        return -1;
    if ( count )
            DPRINTF("invalidated %d tmem pages, check=%d\n",count,checksum);

    return 0;
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
