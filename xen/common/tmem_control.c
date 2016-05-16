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
    bool_t freeze = (arg == XEN_SYSCTL_TMEM_OP_FREEZE) ? 1 : 0;
    bool_t destroy = (arg == XEN_SYSCTL_TMEM_OP_DESTROY) ? 1 : 0;
    char *s;

    s = destroy ? "destroyed" : ( freeze ? "frozen" : "thawed" );
    if ( cli_id == TMEM_CLI_ID_NULL )
    {
        list_for_each_entry(client,&tmem_global.client_list,client_list)
            client->frozen = freeze;
        tmem_client_info("tmem: all pools %s for all %ss\n", s, tmem_client_str);
    }
    else
    {
        if ( (client = tmem_client_from_cli_id(cli_id)) == NULL)
            return -1;
        client->frozen = freeze;
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
                             int off, uint32_t len, bool_t use_long)
{
    char info[BSIZE];
    int i, n = 0, sum = 0;
    struct tmem_pool *p;
    bool_t s;

    n = scnprintf(info,BSIZE,"C=CI:%d,ww:%d,ca:%d,co:%d,fr:%d,"
        "Tc:%"PRIu64",Ge:%ld,Pp:%ld,Gp:%ld%c",
        c->cli_id, c->weight, c->cap, c->compress, c->frozen,
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
                              bool_t use_long)
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
                                  uint32_t len, bool_t use_long)
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
                              bool_t use_long)
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
                               bool_t use_long)
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

static int __tmemc_set_var(struct client *client, uint32_t subop, uint32_t arg1)
{
    domid_t cli_id = client->cli_id;
    uint32_t old_weight;

    switch (subop)
    {
    case XEN_SYSCTL_TMEM_OP_SET_WEIGHT:
        old_weight = client->weight;
        client->weight = arg1;
        tmem_client_info("tmem: weight set to %d for %s=%d\n",
                        arg1, tmem_cli_id_str, cli_id);
        atomic_sub(old_weight,&tmem_global.client_weight_total);
        atomic_add(client->weight,&tmem_global.client_weight_total);
        break;
    case XEN_SYSCTL_TMEM_OP_SET_CAP:
        client->cap = arg1;
        tmem_client_info("tmem: cap set to %d for %s=%d\n",
                        arg1, tmem_cli_id_str, cli_id);
        break;
    case XEN_SYSCTL_TMEM_OP_SET_COMPRESS:
        if ( tmem_dedup_enabled() )
        {
            tmem_client_warn("tmem: compression %s for all %ss, cannot be changed when tmem_dedup is enabled\n",
                            tmem_compression_enabled() ? "enabled" : "disabled",
                            tmem_client_str);
            return -1;
        }
        client->compress = arg1 ? 1 : 0;
        tmem_client_info("tmem: compression %s for %s=%d\n",
            arg1 ? "enabled" : "disabled",tmem_cli_id_str,cli_id);
        break;
    default:
        tmem_client_warn("tmem: unknown subop %d for tmemc_set_var\n", subop);
        return -1;
    }
    return 0;
}

static int tmemc_set_var(domid_t cli_id, uint32_t subop, uint32_t arg1)
{
    struct client *client;
    int ret = -1;

    if ( cli_id == TMEM_CLI_ID_NULL )
    {
        list_for_each_entry(client,&tmem_global.client_list,client_list)
        {
            ret =  __tmemc_set_var(client, subop, arg1);
            if (ret)
                break;
        }
    }
    else
    {
        client = tmem_client_from_cli_id(cli_id);
        if ( client )
            ret = __tmemc_set_var(client, subop, arg1);
    }
    return ret;
}

static int tmemc_save_subop(int cli_id, uint32_t pool_id,
                        uint32_t subop, tmem_cli_va_param_t buf, uint32_t arg1)
{
    struct client *client = tmem_client_from_cli_id(cli_id);
    struct tmem_pool *pool = (client == NULL || pool_id >= MAX_POOLS_PER_DOMAIN)
                   ? NULL : client->pools[pool_id];
    int rc = -1;

    switch(subop)
    {
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_VERSION:
        rc = TMEM_SPEC_VERSION;
        break;
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_MAXPOOLS:
        rc = MAX_POOLS_PER_DOMAIN;
        break;
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_CLIENT_WEIGHT:
        if ( client == NULL )
            break;
        rc = client->weight == -1 ? -2 : client->weight;
        break;
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_CLIENT_CAP:
        if ( client == NULL )
            break;
        rc = client->cap == -1 ? -2 : client->cap;
        break;
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_CLIENT_FLAGS:
        if ( client == NULL )
            break;
        rc = (client->compress ? TMEM_CLIENT_COMPRESS : 0 ) |
             (client->was_frozen ? TMEM_CLIENT_FROZEN : 0 );
        break;
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_POOL_FLAGS:
         if ( pool == NULL )
             break;
         rc = (pool->persistent ? TMEM_POOL_PERSIST : 0) |
              (pool->shared ? TMEM_POOL_SHARED : 0) |
              (POOL_PAGESHIFT << TMEM_POOL_PAGESIZE_SHIFT) |
              (TMEM_SPEC_VERSION << TMEM_POOL_VERSION_SHIFT);
        break;
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_POOL_NPAGES:
         if ( pool == NULL )
             break;
        rc = _atomic_read(pool->pgp_count);
        break;
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_POOL_UUID:
         if ( pool == NULL )
             break;
        rc = 0;
        if ( copy_to_guest(guest_handle_cast(buf, void), pool->uuid, 2) )
            rc = -EFAULT;
        break;
    default:
        rc = -1;
    }
    return rc;
}

int tmem_control(struct xen_sysctl_tmem_op *op)
{
    int ret;
    uint32_t pool_id = op->pool_id;
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
        ret = tmemc_flush_mem(op->cli_id,op->arg1);
        break;
    case XEN_SYSCTL_TMEM_OP_LIST:
        ret = tmemc_list(op->cli_id,
                         guest_handle_cast(op->buf, char), op->arg1, op->arg2);
        break;
    case XEN_SYSCTL_TMEM_OP_SET_WEIGHT:
    case XEN_SYSCTL_TMEM_OP_SET_CAP:
    case XEN_SYSCTL_TMEM_OP_SET_COMPRESS:
        ret = tmemc_set_var(op->cli_id, cmd, op->arg1);
        break;
    case XEN_SYSCTL_TMEM_OP_QUERY_FREEABLE_MB:
        ret = tmem_freeable_pages() >> (20 - PAGE_SHIFT);
        break;
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_VERSION:
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_MAXPOOLS:
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_CLIENT_WEIGHT:
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_CLIENT_CAP:
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_CLIENT_FLAGS:
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_POOL_FLAGS:
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_POOL_NPAGES:
    case XEN_SYSCTL_TMEM_OP_SAVE_GET_POOL_UUID:
        ret = tmemc_save_subop(op->cli_id, pool_id, cmd,
                               guest_handle_cast(op->buf, char), op->arg1);
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
