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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"
#include <xen/tmem.h>

static int do_tmem_op(xc_interface *xch, tmem_op_t *op)
{
    int ret;
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BOUNCE(op, sizeof(*op), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( xc_hypercall_bounce_pre(xch, op) )
    {
        PERROR("Could not bounce buffer for tmem op hypercall");
        return -EFAULT;
    }

    hypercall.op = __HYPERVISOR_tmem_op;
    hypercall.arg[0] = HYPERCALL_BUFFER_AS_ARG(op);
    if ((ret = do_xen_hypercall(xch, &hypercall)) < 0)
    {
        if ( errno == EACCES )
            DPRINTF("tmem operation failed -- need to"
                    " rebuild the user-space tool set?\n");
    }
    xc_hypercall_bounce_post(xch, op);

    return ret;
}

int xc_tmem_control(xc_interface *xch,
                    int32_t pool_id,
                    uint32_t subop,
                    uint32_t cli_id,
                    uint32_t arg1,
                    uint32_t arg2,
                    uint64_t arg3,
                    void *buf)
{
    tmem_op_t op;
    DECLARE_HYPERCALL_BOUNCE(buf, arg1, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int rc;

    op.cmd = TMEM_CONTROL;
    op.pool_id = pool_id;
    op.u.ctrl.subop = subop;
    op.u.ctrl.cli_id = cli_id;
    op.u.ctrl.arg1 = arg1;
    op.u.ctrl.arg2 = arg2;
    /* use xc_tmem_control_oid if arg3 is required */
    op.u.ctrl.oid[0] = 0;
    op.u.ctrl.oid[1] = 0;
    op.u.ctrl.oid[2] = 0;

#ifdef VALGRIND
    if (arg1 != 0)
        memset(buf, 0, arg1);
#endif

    if ( subop == TMEMC_LIST && arg1 != 0 )
    {
        if ( buf == NULL )
            return -EINVAL;
        if ( xc_hypercall_bounce_pre(xch, buf) )
        {
            PERROR("Could not bounce buffer for tmem control hypercall");
            return -ENOMEM;
        }
    }

    set_xen_guest_handle(op.u.ctrl.buf, buf);

    rc = do_tmem_op(xch, &op);

    if (subop == TMEMC_LIST && arg1 != 0)
            xc_hypercall_bounce_post(xch, buf);

    return rc;
}

int xc_tmem_control_oid(xc_interface *xch,
                        int32_t pool_id,
                        uint32_t subop,
                        uint32_t cli_id,
                        uint32_t arg1,
                        uint32_t arg2,
                        struct tmem_oid oid,
                        void *buf)
{
    tmem_op_t op;
    DECLARE_HYPERCALL_BOUNCE(buf, arg1, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int rc;

    op.cmd = TMEM_CONTROL;
    op.pool_id = pool_id;
    op.u.ctrl.subop = subop;
    op.u.ctrl.cli_id = cli_id;
    set_xen_guest_handle(op.u.ctrl.buf,buf);
    op.u.ctrl.arg1 = arg1;
    op.u.ctrl.arg2 = arg2;
    op.u.ctrl.oid[0] = oid.oid[0];
    op.u.ctrl.oid[1] = oid.oid[1];
    op.u.ctrl.oid[2] = oid.oid[2];

#ifdef VALGRIND
    if (arg1 != 0)
        memset(buf, 0, arg1);
#endif

    if ( subop == TMEMC_LIST && arg1 != 0 )
    {
        if ( buf == NULL )
            return -EINVAL;
        if ( xc_hypercall_bounce_pre(xch, buf) )
        {
            PERROR("Could not bounce buffer for tmem control (OID) hypercall");
            return -ENOMEM;
        }
    }

    set_xen_guest_handle(op.u.ctrl.buf, buf);

    rc = do_tmem_op(xch, &op);

    if (subop == TMEMC_LIST && arg1 != 0)
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
            digit = *p - 'A';
        else if ( *p >= 'a' && *p <= 'f' )
            digit = *p - 'a';
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
                 int arg1)
{
    tmem_op_t op;

    op.cmd = TMEM_AUTH;
    op.pool_id = 0;
    op.u.creat.arg1 = cli_id;
    op.u.creat.flags = arg1;
    if ( xc_tmem_uuid_parse(uuid_str, &op.u.creat.uuid[0],
                                      &op.u.creat.uuid[1]) < 0 )
    {
        PERROR("Can't parse uuid, use xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx");
        return -1;
    }

    return do_tmem_op(xch, &op);
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
                 int dom, int io_fd, int live, int field_marker)
{
    int marker = field_marker;
    int i, j;
    uint32_t max_pools, version;
    uint32_t weight, cap, flags;
    uint32_t pool_id;
    uint32_t minusone = -1;
    struct tmem_handle *h;

    if ( xc_tmem_control(xch,0,TMEMC_SAVE_BEGIN,dom,live,0,0,NULL) <= 0 )
        return 0;

    if ( write_exact(io_fd, &marker, sizeof(marker)) )
        return -1;
    version = xc_tmem_control(xch,0,TMEMC_SAVE_GET_VERSION,0,0,0,0,NULL);
    if ( write_exact(io_fd, &version, sizeof(version)) )
        return -1;
    max_pools = xc_tmem_control(xch,0,TMEMC_SAVE_GET_MAXPOOLS,0,0,0,0,NULL);
    if ( write_exact(io_fd, &max_pools, sizeof(max_pools)) )
        return -1;
    if ( version == -1 || max_pools == -1 )
        return -1;
    if ( write_exact(io_fd, &minusone, sizeof(minusone)) )
        return -1;
    flags = xc_tmem_control(xch,0,TMEMC_SAVE_GET_CLIENT_FLAGS,dom,0,0,0,NULL);
    if ( write_exact(io_fd, &flags, sizeof(flags)) )
        return -1;
    weight = xc_tmem_control(xch,0,TMEMC_SAVE_GET_CLIENT_WEIGHT,dom,0,0,0,NULL);
    if ( write_exact(io_fd, &weight, sizeof(weight)) )
        return -1;
    cap = xc_tmem_control(xch,0,TMEMC_SAVE_GET_CLIENT_CAP,dom,0,0,0,NULL);
    if ( write_exact(io_fd, &cap, sizeof(cap)) )
        return -1;
    if ( flags == -1 || weight == -1 || cap == -1 )
        return -1;
    if ( write_exact(io_fd, &minusone, sizeof(minusone)) )
        return -1;
    for ( i = 0; i < max_pools; i++ )
    {
        uint64_t uuid[2];
        uint32_t n_pages;
        uint32_t pagesize;
        char *buf = NULL;
        int bufsize = 0;
        int checksum = 0;

        /* get pool id, flags, pagesize, n_pages, uuid */
        flags = xc_tmem_control(xch,i,TMEMC_SAVE_GET_POOL_FLAGS,dom,0,0,0,NULL);
        if ( flags != -1 )
        {
            pool_id = i;
            n_pages = xc_tmem_control(xch,i,TMEMC_SAVE_GET_POOL_NPAGES,dom,0,0,0,NULL);
            if ( !(flags & TMEM_POOL_PERSIST) )
                n_pages = 0;
            (void)xc_tmem_control(xch,i,TMEMC_SAVE_GET_POOL_UUID,dom,sizeof(uuid),0,0,&uuid);
            if ( write_exact(io_fd, &pool_id, sizeof(pool_id)) )
                return -1;
            if ( write_exact(io_fd, &flags, sizeof(flags)) )
                return -1;
            if ( write_exact(io_fd, &n_pages, sizeof(n_pages)) )
                return -1;
            if ( write_exact(io_fd, &uuid, sizeof(uuid)) )
                return -1;
            if ( n_pages == 0 )
                continue;

            pagesize = 1 << (((flags >> TMEM_POOL_PAGESIZE_SHIFT) &
                              TMEM_POOL_PAGESIZE_MASK) + 12);
            if ( pagesize > bufsize )
            {
                bufsize = pagesize + sizeof(struct tmem_handle);
                if ( (buf = realloc(buf,bufsize)) == NULL )
                    return -1;
            }
            for ( j = n_pages; j > 0; j-- )
            {
                int ret;
                if ( (ret = xc_tmem_control(xch, pool_id,
                                            TMEMC_SAVE_GET_NEXT_PAGE, dom,
                                            bufsize, 0, 0, buf)) > 0 )
                {
                    h = (struct tmem_handle *)buf;
                    if ( write_exact(io_fd, &h->oid, sizeof(h->oid)) )
                        return -1;
                    if ( write_exact(io_fd, &h->index, sizeof(h->index)) )
                        return -1;
                    h++;
                    checksum += *(char *)h;
                    if ( write_exact(io_fd, h, pagesize) )
                        return -1;
                } else if ( ret == 0 ) {
                    continue;
                } else {
                    /* page list terminator */
                    h = (struct tmem_handle *)buf;
                    h->oid[0] = h->oid[1] = h->oid[2] = -1L;
                    if ( write_exact(io_fd, &h->oid, sizeof(h->oid)) )
                        return -1;
                    break;
                }
            }
            DPRINTF("saved %d tmem pages for dom=%d pool=%d, checksum=%x\n",
                         n_pages-j,dom,pool_id,checksum);
        }
    }
    /* pool list terminator */
    minusone = -1;
    if ( write_exact(io_fd, &minusone, sizeof(minusone)) )
        return -1;

    return 1;
}

/* only called for live migration */
int xc_tmem_save_extra(xc_interface *xch, int dom, int io_fd, int field_marker)
{
    struct tmem_handle handle;
    int marker = field_marker;
    uint32_t minusone;
    int count = 0, checksum = 0;

    if ( write_exact(io_fd, &marker, sizeof(marker)) )
        return -1;
    while ( xc_tmem_control(xch, 0, TMEMC_SAVE_GET_NEXT_INV, dom,
                            sizeof(handle),0,0,&handle) > 0 ) {
        if ( write_exact(io_fd, &handle.pool_id, sizeof(handle.pool_id)) )
            return -1;
        if ( write_exact(io_fd, &handle.oid, sizeof(handle.oid)) )
            return -1;
        if ( write_exact(io_fd, &handle.index, sizeof(handle.index)) )
            return -1;
        count++;
        checksum += handle.pool_id + handle.oid[0] + handle.oid[1] +
                    handle.oid[2] + handle.index;
    }
    if ( count )
            DPRINTF("needed %d tmem invalidates, check=%d\n",count,checksum);
    minusone = -1;
    if ( write_exact(io_fd, &minusone, sizeof(minusone)) )
        return -1;
    return 0;
}

/* only called for live migration */
void xc_tmem_save_done(xc_interface *xch, int dom)
{
    xc_tmem_control(xch,0,TMEMC_SAVE_END,dom,0,0,0,NULL);
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
    tmem_op_t op;

    op.cmd = TMEM_RESTORE_NEW;
    op.pool_id = pool_id;
    op.u.creat.arg1 = cli_id;
    op.u.creat.flags = flags;
    op.u.creat.uuid[0] = uuid_lo;
    op.u.creat.uuid[1] = uuid_hi;

    return do_tmem_op(xch, &op);
}

int xc_tmem_restore(xc_interface *xch, int dom, int io_fd)
{
    uint32_t save_version;
    uint32_t this_max_pools, this_version;
    uint32_t pool_id;
    uint32_t minusone;
    uint32_t weight, cap, flags;
    int checksum = 0;

    save_version = xc_tmem_control(xch,0,TMEMC_SAVE_GET_VERSION,dom,0,0,0,NULL);
    if ( save_version == -1 )
        return -1; /* domain doesn't exist */
    if ( read_exact(io_fd, &this_version, sizeof(this_version)) )
        return -1;
    if ( read_exact(io_fd, &this_max_pools, sizeof(this_max_pools)) )
        return -1;
    /* FIXME check here to ensure no version mismatch or maxpools mismatch */
    if ( read_exact(io_fd, &minusone, sizeof(minusone)) )
        return -1;
    if ( minusone != -1 )
        return -1;
    if ( xc_tmem_control(xch,0,TMEMC_RESTORE_BEGIN,dom,0,0,0,NULL) < 0 )
        return -1;
    if ( read_exact(io_fd, &flags, sizeof(flags)) )
        return -1;
    if ( flags & TMEM_CLIENT_COMPRESS )
        if ( xc_tmem_control(xch,0,TMEMC_SET_COMPRESS,dom,1,0,0,NULL) < 0 )
            return -1;
    if ( flags & TMEM_CLIENT_FROZEN )
        if ( xc_tmem_control(xch,0,TMEMC_FREEZE,dom,0,0,0,NULL) < 0 )
            return -1;
    if ( read_exact(io_fd, &weight, sizeof(weight)) )
        return -1;
    if ( xc_tmem_control(xch,0,TMEMC_SET_WEIGHT,dom,0,0,0,NULL) < 0 )
        return -1;
    if ( read_exact(io_fd, &cap, sizeof(cap)) )
        return -1;
    if ( xc_tmem_control(xch,0,TMEMC_SET_CAP,dom,0,0,0,NULL) < 0 )
        return -1;
    if ( read_exact(io_fd, &minusone, sizeof(minusone)) )
        return -1;
    while ( read_exact(io_fd, &pool_id, sizeof(pool_id)) == 0 && pool_id != -1 )
    {
        uint64_t uuid[2];
        uint32_t n_pages;
        char *buf = NULL;
        int bufsize = 0, pagesize;
        int j;

        if ( read_exact(io_fd, &flags, sizeof(flags)) )
            return -1;
        if ( read_exact(io_fd, &n_pages, sizeof(n_pages)) )
            return -1;
        if ( read_exact(io_fd, &uuid, sizeof(uuid)) )
            return -1;
        if ( xc_tmem_restore_new_pool(xch, dom, pool_id,
                                 flags, uuid[0], uuid[1]) < 0)
            return -1;
        if ( n_pages <= 0 )
            continue;

        pagesize = 1 << (((flags >> TMEM_POOL_PAGESIZE_SHIFT) &
                              TMEM_POOL_PAGESIZE_MASK) + 12);
        if ( pagesize > bufsize )
        {
            bufsize = pagesize;
            if ( (buf = realloc(buf,bufsize)) == NULL )
                return -1;
        }
        for ( j = n_pages; j > 0; j-- )
        {
            struct tmem_oid oid;
            uint32_t index;
            int rc;
            if ( read_exact(io_fd, &oid, sizeof(oid)) )
                return -1;
            if ( oid.oid[0] == -1L && oid.oid[1] == -1L && oid.oid[2] == -1L )
                break;
            if ( read_exact(io_fd, &index, sizeof(index)) )
                return -1;
            if ( read_exact(io_fd, buf, pagesize) )
                return -1;
            checksum += *buf;
            if ( (rc = xc_tmem_control_oid(xch, pool_id,
                                           TMEMC_RESTORE_PUT_PAGE, dom,
                                           bufsize, index, oid, buf)) <= 0 )
            {
                DPRINTF("xc_tmem_restore: putting page failed, rc=%d\n",rc);
                return -1;
            }
        }
        if ( n_pages )
            DPRINTF("restored %d tmem pages for dom=%d pool=%d, check=%x\n",
                    n_pages-j,dom,pool_id,checksum);
    }
    if ( pool_id != -1 )
        return -1;

    return 0;
}

/* only called for live migration, must be called after suspend */
int xc_tmem_restore_extra(xc_interface *xch, int dom, int io_fd)
{
    uint32_t pool_id;
    struct tmem_oid oid;
    uint32_t index;
    int count = 0;
    int checksum = 0;

    while ( read_exact(io_fd, &pool_id, sizeof(pool_id)) == 0 && pool_id != -1 )
    {
        if ( read_exact(io_fd, &oid, sizeof(oid)) )
            return -1;
        if ( read_exact(io_fd, &index, sizeof(index)) )
            return -1;
        if ( xc_tmem_control_oid(xch, pool_id, TMEMC_RESTORE_FLUSH_PAGE, dom,
                             0,index,oid,NULL) <= 0 )
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
