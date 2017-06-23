/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include <xen/init.h>
#include <xen/list.h>
#include <xen/radix-tree.h>
#include <xen/rbtree.h>
#include <xen/rwlock.h>
#include <xen/tmem_control.h>
#include <xen/tmem.h>
#include <xen/tmem_xen.h>
#include <public/sysctl.h>

/************ TMEM CONTROL OPERATIONS ************************************/

/* Freeze/thaw all pools belonging to client cli_id (all domains if -1). */
static int tmemc_freeze_pools(domid_t cli_id, int arg)
{
    struct client *client;
    bool freeze = arg == XEN_SYSCTL_TMEM_OP_FREEZE;
    bool destroy = arg == XEN_SYSCTL_TMEM_OP_DESTROY;
    char *s;

    s = destroy ? "destroyed" : ( freeze ? "frozen" : "thawed" );
    if ( cli_id == TMEM_CLI_ID_NULL )
    {
        list_for_each_entry(client,&tmem_global.client_list,client_list)
            client->info.flags.u.frozen = freeze;
        tmem_client_info("tmem: all pools %s for all %ss\n", s, tmem_client_str);
    }
    else
    {
        if ( (client = tmem_client_from_cli_id(cli_id)) == NULL)
            return -1;
        client->info.flags.u.frozen = freeze;
        tmem_client_info("tmem: all pools %s for %s=%d\n",
                         s, tmem_cli_id_str, cli_id);
    }
    return 0;
}

static unsigned long tmem_flush_npages(unsigned long n)
{
    unsigned long avail_pages = 0;

    while ( (avail_pages = tmem_page_list_pages) < n )
    {
        if (  !tmem_evict() )
            break;
    }
    if ( avail_pages )
    {
        spin_lock(&tmem_page_list_lock);
        while ( !page_list_empty(&tmem_page_list) )
        {
            struct page_info *pg = page_list_remove_head(&tmem_page_list);
            scrub_one_page(pg);
            tmem_page_list_pages--;
            free_domheap_page(pg);
        }
        ASSERT(tmem_page_list_pages == 0);
        INIT_PAGE_LIST_HEAD(&tmem_page_list);
        spin_unlock(&tmem_page_list_lock);
    }
    return avail_pages;
}

static int tmemc_flush_mem(domid_t cli_id, uint32_t kb)
{
    uint32_t npages, flushed_pages, flushed_kb;

    if ( cli_id != TMEM_CLI_ID_NULL )
    {
        tmem_client_warn("tmem: %s-specific flush not supported yet, use --all\n",
           tmem_client_str);
        return -1;
    }
    /* Convert kb to pages, rounding up if necessary. */
    npages = (kb + ((1 << (PAGE_SHIFT-10))-1)) >> (PAGE_SHIFT-10);
    flushed_pages = tmem_flush_npages(npages);
    flushed_kb = flushed_pages << (PAGE_SHIFT-10);
    return flushed_kb;
}

/*
 * These tmemc_list* routines output lots of stats in a format that is
 *  intended to be program-parseable, not human-readable. Further, by
 *  tying each group of stats to a line format indicator (e.g. G= for
 *  global stats) and each individual stat to a two-letter specifier
 *  (e.g. Ec:nnnnn in the G= line says there are nnnnn pages in the
 *  global ephemeral pool), it should allow the stats reported to be
 *  forward and backwards compatible as tmem evolves.
 */
#define BSIZE 1024

static int tmemc_list_client(struct client *c, tmem_cli_va_param_t buf,
                             int off, uint32_t len, bool use_long)
{
    char info[BSIZE];
    int i, n = 0, sum = 0;
    struct tmem_pool *p;
    bool s;

    n = scnprintf(info,BSIZE,"C=CI:%d,ww:%d,co:%d,fr:%d,"
        "Tc:%"PRIu64",Ge:%ld,Pp:%ld,Gp:%ld%c",
        c->cli_id, c->info.weight, c->info.flags.u.compress, c->info.flags.u.frozen,
        c->total_cycles, c->succ_eph_gets, c->succ_pers_puts, c->succ_pers_gets,
        use_long ? ',' : '\n');
    if (use_long)
        n += scnprintf(info+n,BSIZE-n,
             "Ec:%ld,Em:%ld,cp:%ld,cb:%"PRId64",cn:%ld,cm:%ld\n",
             c->eph_count, c->eph_count_max,
             c->compressed_pages, c->compressed_sum_size,
             c->compress_poor, c->compress_nomem);
    if ( !copy_to_guest_offset(buf, off + sum, info, n + 1) )
        sum += n;
    for ( i = 0; i < MAX_POOLS_PER_DOMAIN; i++ )
    {
        if ( (p = c->pools[i]) == NULL )
            continue;
        s = is_shared(p);
        n = scnprintf(info,BSIZE,"P=CI:%d,PI:%d,"
                      "PT:%c%c,U0:%"PRIx64",U1:%"PRIx64"%c",
                      c->cli_id, p->pool_id,
                      is_persistent(p) ? 'P' : 'E', s ? 'S' : 'P',
                      (uint64_t)(s ? p->uuid[0] : 0),
                      (uint64_t)(s ? p->uuid[1] : 0LL),
                      use_long ? ',' : '\n');
        if (use_long)
            n += scnprintf(info+n,BSIZE-n,
             "Pc:%d,Pm:%d,Oc:%ld,Om:%ld,Nc:%lu,Nm:%lu,"
             "ps:%lu,pt:%lu,pd:%lu,pr:%lu,px:%lu,gs:%lu,gt:%lu,"
             "fs:%lu,ft:%lu,os:%lu,ot:%lu\n",
             _atomic_read(p->pgp_count), p->pgp_count_max,
             p->obj_count, p->obj_count_max,
             p->objnode_count, p->objnode_count_max,
             p->good_puts, p->puts,p->dup_puts_flushed, p->dup_puts_replaced,
             p->no_mem_puts,
             p->found_gets, p->gets,
             p->flushs_found, p->flushs, p->flush_objs_found, p->flush_objs);
        if ( sum + n >= len )
            return sum;
        if ( !copy_to_guest_offset(buf, off + sum, info, n + 1) )
            sum += n;
    }
    return sum;
}

static int tmemc_list_shared(tmem_cli_va_param_t buf, int off, uint32_t len,
                             bool use_long)
{
    char info[BSIZE];
    int i, n = 0, sum = 0;
    struct tmem_pool *p;
    struct share_list *sl;

    for ( i = 0; i < MAX_GLOBAL_SHARED_POOLS; i++ )
    {
        if ( (p = tmem_global.shared_pools[i]) == NULL )
            continue;
        n = scnprintf(info+n,BSIZE-n,"S=SI:%d,PT:%c%c,U0:%"PRIx64",U1:%"PRIx64,
                      i, is_persistent(p) ? 'P' : 'E',
                      is_shared(p) ? 'S' : 'P',
                      p->uuid[0], p->uuid[1]);
        list_for_each_entry(sl,&p->share_list, share_list)
            n += scnprintf(info+n,BSIZE-n,",SC:%d",sl->client->cli_id);
        n += scnprintf(info+n,BSIZE-n,"%c", use_long ? ',' : '\n');
        if (use_long)
            n += scnprintf(info+n,BSIZE-n,
             "Pc:%d,Pm:%d,Oc:%ld,Om:%ld,Nc:%lu,Nm:%lu,"
             "ps:%lu,pt:%lu,pd:%lu,pr:%lu,px:%lu,gs:%lu,gt:%lu,"
             "fs:%lu,ft:%lu,os:%lu,ot:%lu\n",
             _atomic_read(p->pgp_count), p->pgp_count_max,
             p->obj_count, p->obj_count_max,
             p->objnode_count, p->objnode_count_max,
             p->good_puts, p->puts,p->dup_puts_flushed, p->dup_puts_replaced,
             p->no_mem_puts,
             p->found_gets, p->gets,
             p->flushs_found, p->flushs, p->flush_objs_found, p->flush_objs);
        if ( sum + n >= len )
            return sum;
        if ( !copy_to_guest_offset(buf, off + sum, info, n + 1) )
            sum += n;
    }
    return sum;
}

static int tmemc_list_global_perf(tmem_cli_va_param_t buf, int off,
                                  uint32_t len, bool use_long)
{
    char info[BSIZE];
    int n = 0, sum = 0;

    n = scnprintf(info+n,BSIZE-n,"T=");
    n--; /* Overwrite trailing comma. */
    n += scnprintf(info+n,BSIZE-n,"\n");
    if ( sum + n >= len )
        return sum;
    if ( !copy_to_guest_offset(buf, off + sum, info, n + 1) )
        sum += n;
    return sum;
}

static int tmemc_list_global(tmem_cli_va_param_t buf, int off, uint32_t len,
                             bool use_long)
{
    char info[BSIZE];
    int n = 0, sum = off;

    n += scnprintf(info,BSIZE,"G="
      "Tt:%lu,Te:%lu,Cf:%lu,Af:%lu,Pf:%lu,Ta:%lu,"
      "Lm:%lu,Et:%lu,Ea:%lu,Rt:%lu,Ra:%lu,Rx:%lu,Fp:%lu%c",
      tmem_stats.total_tmem_ops, tmem_stats.errored_tmem_ops, tmem_stats.failed_copies,
      tmem_stats.alloc_failed, tmem_stats.alloc_page_failed, tmem_page_list_pages,
      tmem_stats.low_on_memory, tmem_stats.evicted_pgs,
      tmem_stats.evict_attempts, tmem_stats.relinq_pgs, tmem_stats.relinq_attempts,
      tmem_stats.max_evicts_per_relinq,
      tmem_stats.total_flush_pool, use_long ? ',' : '\n');
    if (use_long)
        n += scnprintf(info+n,BSIZE-n,
          "Ec:%ld,Em:%ld,Oc:%d,Om:%d,Nc:%d,Nm:%d,Pc:%d,Pm:%d,"
          "Fc:%d,Fm:%d,Sc:%d,Sm:%d,Ep:%lu,Gd:%lu,Zt:%lu,Gz:%lu\n",
          tmem_global.eph_count, tmem_stats.global_eph_count_max,
          _atomic_read(tmem_stats.global_obj_count), tmem_stats.global_obj_count_max,
          _atomic_read(tmem_stats.global_rtree_node_count), tmem_stats.global_rtree_node_count_max,
          _atomic_read(tmem_stats.global_pgp_count), tmem_stats.global_pgp_count_max,
          _atomic_read(tmem_stats.global_page_count), tmem_stats.global_page_count_max,
          _atomic_read(tmem_stats.global_pcd_count), tmem_stats.global_pcd_count_max,
         tmem_stats.tot_good_eph_puts,tmem_stats.deduped_puts,tmem_stats.pcd_tot_tze_size,
         tmem_stats.pcd_tot_csize);
    if ( sum + n >= len )
        return sum;
    if ( !copy_to_guest_offset(buf, off + sum, info, n + 1) )
        sum += n;
    return sum;
}

static int tmemc_list(domid_t cli_id, tmem_cli_va_param_t buf, uint32_t len,
                      bool use_long)
{
    struct client *client;
    int off = 0;

    if ( cli_id == TMEM_CLI_ID_NULL ) {
        off = tmemc_list_global(buf,0,len,use_long);
        off += tmemc_list_shared(buf,off,len-off,use_long);
        list_for_each_entry(client,&tmem_global.client_list,client_list)
            off += tmemc_list_client(client, buf, off, len-off, use_long);
        off += tmemc_list_global_perf(buf,off,len-off,use_long);
    }
    else if ( (client = tmem_client_from_cli_id(cli_id)) == NULL)
        return -1;
    else
        off = tmemc_list_client(client, buf, 0, len, use_long);

    return 0;
}

static int __tmemc_set_client_info(struct client *client,
                                   XEN_GUEST_HANDLE(xen_tmem_client_t) buf)
{
    domid_t cli_id;
    uint32_t old_weight;
    xen_tmem_client_t info = { };

    ASSERT(client);

    if ( copy_from_guest(&info, buf, 1) )
        return -EFAULT;

    if ( info.version != TMEM_SPEC_VERSION )
        return -EOPNOTSUPP;

    if ( info.maxpools > MAX_POOLS_PER_DOMAIN )
        return -ERANGE;

    /* Ignore info.nr_pools. */
    cli_id = client->cli_id;

    if ( info.weight != client->info.weight )
    {
        old_weight = client->info.weight;
        client->info.weight = info.weight;
        tmem_client_info("tmem: weight set to %d for %s=%d\n",
                         info.weight, tmem_cli_id_str, cli_id);
        atomic_sub(old_weight,&tmem_global.client_weight_total);
        atomic_add(client->info.weight,&tmem_global.client_weight_total);
    }


    if ( info.flags.u.compress != client->info.flags.u.compress )
    {
        client->info.flags.u.compress = info.flags.u.compress;
        tmem_client_info("tmem: compression %s for %s=%d\n",
                         info.flags.u.compress ? "enabled" : "disabled",
                         tmem_cli_id_str,cli_id);
    }
    return 0;
}

static int tmemc_set_client_info(domid_t cli_id,
                                 XEN_GUEST_HANDLE(xen_tmem_client_t) info)
{
    struct client *client;
    int ret = -ENOENT;

    if ( cli_id == TMEM_CLI_ID_NULL )
    {
        list_for_each_entry(client,&tmem_global.client_list,client_list)
        {
            ret =  __tmemc_set_client_info(client, info);
            if (ret)
                break;
        }
    }
    else
    {
        client = tmem_client_from_cli_id(cli_id);
        if ( client )
            ret = __tmemc_set_client_info(client, info);
    }
    return ret;
}

static int tmemc_get_client_info(int cli_id,
                                 XEN_GUEST_HANDLE(xen_tmem_client_t) info)
{
    struct client *client = tmem_client_from_cli_id(cli_id);

    if ( client )
    {
        if ( copy_to_guest(info, &client->info, 1) )
            return  -EFAULT;
    }
    else
    {
        static const xen_tmem_client_t generic = {
            .version = TMEM_SPEC_VERSION,
            .maxpools = MAX_POOLS_PER_DOMAIN
        };

        if ( copy_to_guest(info, &generic, 1) )
            return -EFAULT;
    }

    return 0;
}

static int tmemc_get_pool(int cli_id,
                          XEN_GUEST_HANDLE(xen_tmem_pool_info_t) pools,
                          uint32_t len)
{
    struct client *client = tmem_client_from_cli_id(cli_id);
    unsigned int i, idx;
    int rc = 0;
    unsigned int nr = len / sizeof(xen_tmem_pool_info_t);

    if ( len % sizeof(xen_tmem_pool_info_t) )
        return -EINVAL;

    if ( nr > MAX_POOLS_PER_DOMAIN )
        return -E2BIG;

    if ( !guest_handle_okay(pools, nr) )
        return -EINVAL;

    if ( !client )
        return -EINVAL;

    for ( idx = 0, i = 0; i < MAX_POOLS_PER_DOMAIN; i++ )
    {
        struct tmem_pool *pool = client->pools[i];
        xen_tmem_pool_info_t out;

        if ( pool == NULL )
            continue;

        out.flags.raw = (pool->persistent ? TMEM_POOL_PERSIST : 0) |
              (pool->shared ? TMEM_POOL_SHARED : 0) |
              (POOL_PAGESHIFT << TMEM_POOL_PAGESIZE_SHIFT) |
              (TMEM_SPEC_VERSION << TMEM_POOL_VERSION_SHIFT);
        out.n_pages = _atomic_read(pool->pgp_count);
        out.uuid[0] = pool->uuid[0];
        out.uuid[1] = pool->uuid[1];
        out.id = i;

        /* N.B. 'idx' != 'i'. */
        if ( __copy_to_guest_offset(pools, idx, &out, 1) )
        {
            rc = -EFAULT;
            break;
        }
        idx++;
        /* Don't try to put more than what was requested. */
        if ( idx >= nr )
            break;
    }

    /* And how many we have processed. */
    return rc ? : idx;
}

static int tmemc_set_pools(int cli_id,
                           XEN_GUEST_HANDLE(xen_tmem_pool_info_t) pools,
                           uint32_t len)
{
    unsigned int i;
    int rc = 0;
    unsigned int nr = len / sizeof(xen_tmem_pool_info_t);
    struct client *client = tmem_client_from_cli_id(cli_id);

    if ( len % sizeof(xen_tmem_pool_info_t) )
        return -EINVAL;

    if ( nr > MAX_POOLS_PER_DOMAIN )
        return -E2BIG;

    if ( !guest_handle_okay(pools, nr) )
        return -EINVAL;

    if ( !client )
    {
        client = client_create(cli_id);
        if ( !client )
            return -ENOMEM;
    }
    for ( i = 0; i < nr; i++ )
    {
        xen_tmem_pool_info_t pool;

        if ( __copy_from_guest_offset(&pool, pools, i, 1 ) )
            return -EFAULT;

        if ( pool.n_pages )
            return -EINVAL;

        rc = do_tmem_new_pool(cli_id, pool.id, pool.flags.raw,
                              pool.uuid[0], pool.uuid[1]);
        if ( rc < 0 )
            break;

        pool.id = rc;
        if ( __copy_to_guest_offset(pools, i, &pool, 1) )
            return -EFAULT;
    }

    /* And how many we have processed. */
    return rc ? : i;
}

static int tmemc_auth_pools(int cli_id,
                            XEN_GUEST_HANDLE(xen_tmem_pool_info_t) pools,
                            uint32_t len)
{
    unsigned int i;
    int rc = 0;
    unsigned int nr = len / sizeof(xen_tmem_pool_info_t);
    struct client *client = tmem_client_from_cli_id(cli_id);

    if ( len % sizeof(xen_tmem_pool_info_t) )
        return -EINVAL;

    if ( nr > MAX_POOLS_PER_DOMAIN )
        return -E2BIG;

    if ( !guest_handle_okay(pools, nr) )
        return -EINVAL;

    if ( !client )
    {
        client = client_create(cli_id);
        if ( !client )
            return -ENOMEM;
    }

    for ( i = 0; i < nr; i++ )
    {
        xen_tmem_pool_info_t pool;

        if ( __copy_from_guest_offset(&pool, pools, i, 1 ) )
            return -EFAULT;

        if ( pool.n_pages )
            return -EINVAL;

        rc = tmemc_shared_pool_auth(cli_id, pool.uuid[0], pool.uuid[1],
                                    pool.flags.u.auth);

        if ( rc < 0 )
            break;

    }

    /* And how many we have processed. */
    return rc ? : i;
}

int tmem_control(struct xen_sysctl_tmem_op *op)
{
    int ret;
    uint32_t cmd = op->cmd;

    if ( op->pad != 0 )
        return -EINVAL;

    write_lock(&tmem_rwlock);

    switch (cmd)
    {
    case XEN_SYSCTL_TMEM_OP_THAW:
    case XEN_SYSCTL_TMEM_OP_FREEZE:
    case XEN_SYSCTL_TMEM_OP_DESTROY:
        ret = tmemc_freeze_pools(op->cli_id, cmd);
        break;
    case XEN_SYSCTL_TMEM_OP_FLUSH:
        ret = tmemc_flush_mem(op->cli_id, op->arg);
        break;
    case XEN_SYSCTL_TMEM_OP_LIST:
        ret = tmemc_list(op->cli_id,
                         guest_handle_cast(op->u.buf, char), op->len, op->arg);
        break;
    case XEN_SYSCTL_TMEM_OP_SET_CLIENT_INFO:
        ret = tmemc_set_client_info(op->cli_id, op->u.client);
        break;
    case XEN_SYSCTL_TMEM_OP_QUERY_FREEABLE_MB:
        ret = tmem_freeable_pages() >> (20 - PAGE_SHIFT);
        break;
    case XEN_SYSCTL_TMEM_OP_GET_CLIENT_INFO:
        ret = tmemc_get_client_info(op->cli_id, op->u.client);
        break;
    case XEN_SYSCTL_TMEM_OP_GET_POOLS:
        ret = tmemc_get_pool(op->cli_id, op->u.pool, op->len);
        break;
    case XEN_SYSCTL_TMEM_OP_SET_POOLS: /* TMEM_RESTORE_NEW */
        ret = tmemc_set_pools(op->cli_id, op->u.pool, op->len);
        break;
    case XEN_SYSCTL_TMEM_OP_SET_AUTH: /* TMEM_AUTH */
        ret = tmemc_auth_pools(op->cli_id, op->u.pool, op->len);
        break;
    default:
        ret = do_tmem_control(op);
        break;
    }

    write_unlock(&tmem_rwlock);

    return ret;
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
