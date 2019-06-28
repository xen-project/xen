/*
 * xen/arch/arm/tee/optee.c
 *
 * OP-TEE mediator. It sits in between OP-TEE and guests and performs
 * actual calls to OP-TEE when some guest tries to interact with
 * OP-TEE. As OP-TEE does not know about second stage MMU translation,
 * mediator does this translation and performs other housekeeping tasks.
 *
 * OP-TEE ABI/protocol is described in two header files:
 *  - optee_smc.h provides information about SMCs: all possible calls,
 *    register allocation and return codes.
 *  - optee_msg.h provides format for messages that are passed with
 *    standard call OPTEE_SMC_CALL_WITH_ARG.
 *
 * Volodymyr Babchuk <volodymyr_babchuk@epam.com>
 * Copyright (c) 2018-2019 EPAM Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/device_tree.h>
#include <xen/domain_page.h>
#include <xen/err.h>
#include <xen/guest_access.h>
#include <xen/mm.h>
#include <xen/sched.h>

#include <asm/event.h>
#include <asm/smccc.h>
#include <asm/tee/tee.h>
#include <asm/tee/optee_msg.h>
#include <asm/tee/optee_smc.h>
#include <asm/tee/optee_rpc_cmd.h>

/* Number of SMCs known to the mediator */
#define OPTEE_MEDIATOR_SMC_COUNT   11

/*
 * "The return code is an error that originated within the underlying
 * communications stack linking the rich OS with the TEE" as described
 * in GP TEE Client API Specification.
 */
#define TEEC_ORIGIN_COMMS 0x00000002

/* "Non-specific cause" as in GP TEE Client API Specification */
#define TEEC_ERROR_GENERIC 0xFFFF0000

/*
 * "Input parameters were invalid" as described
 * in GP TEE Client API Specification.
 */
#define TEEC_ERROR_BAD_PARAMETERS 0xFFFF0006

/* "System ran out of resources" as in GP TEE Client API Specification */
#define TEEC_ERROR_OUT_OF_MEMORY 0xFFFF000C

/* Client ID 0 is reserved for the hypervisor itself */
#define OPTEE_CLIENT_ID(domain) ((domain)->domain_id + 1)

/*
 * Maximum total number of pages that guest can share with
 * OP-TEE. Currently value is selected arbitrary. Actual number of
 * pages depends on free heap in OP-TEE. As we can't do any
 * assumptions about OP-TEE heap usage, we limit number of pages
 * arbitrary.
 */
#define MAX_TOTAL_SMH_BUF_PG    16384

#define OPTEE_KNOWN_NSEC_CAPS OPTEE_SMC_NSEC_CAP_UNIPROCESSOR
#define OPTEE_KNOWN_SEC_CAPS (OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM | \
                              OPTEE_SMC_SEC_CAP_UNREGISTERED_SHM | \
                              OPTEE_SMC_SEC_CAP_DYNAMIC_SHM)

static unsigned int __read_mostly max_optee_threads;

/*
 * Call context. OP-TEE can issue multiple RPC returns during one call.
 * We need to preserve context during them.
 */
struct optee_std_call {
    struct list_head list;
    /* Page where shadowed copy of call arguments is stored */
    struct page_info *xen_arg_pg;
    /* Above page mapped into XEN */
    struct optee_msg_arg *xen_arg;
    /* Address of original call arguments */
    paddr_t guest_arg_ipa;
    int optee_thread_id;
    int rpc_op;
    uint64_t rpc_data_cookie;
    bool in_flight;
    register_t rpc_params[2];
};

/* Pre-allocated SHM buffer for RPC commands */
struct shm_rpc {
    struct list_head list;
    struct page_info *guest_page;
    struct page_info *xen_arg_pg;
    struct optee_msg_arg *xen_arg;
    gfn_t gfn;
    uint64_t cookie;
};

/* Shared memory buffer for arbitrary data */
struct optee_shm_buf {
    struct list_head list;
    uint64_t cookie;
    unsigned int page_cnt;
    /*
     * Shadowed container for list of pages that guest tries to share
     * with OP-TEE. This is not the list of pages that guest shared
     * with OP-TEE, but container for list of those pages. Check
     * OPTEE_MSG_ATTR_NONCONTIG definition in optee_msg.h for more
     * information.
     */
    struct page_info *pg_list;
    unsigned int pg_list_order;
    /* Pinned guest pages that are shared with OP-TEE */
    struct page_info *pages[];
};

/* Domain context */
struct optee_domain {
    struct list_head call_list;
    struct list_head shm_rpc_list;
    struct list_head optee_shm_buf_list;
    atomic_t call_count;
    atomic_t optee_shm_buf_pages;
    spinlock_t lock;
};

static bool optee_probe(void)
{
    struct dt_device_node *node;
    struct arm_smccc_res resp;

    /* Check for entry in dtb */
    node = dt_find_compatible_node(NULL, NULL, "linaro,optee-tz");
    if ( !node )
        return false;

    /* Check UID */
    arm_smccc_smc(ARM_SMCCC_CALL_UID_FID(TRUSTED_OS_END), &resp);

    if ( (uint32_t)resp.a0 != OPTEE_MSG_UID_0 ||
         (uint32_t)resp.a1 != OPTEE_MSG_UID_1 ||
         (uint32_t)resp.a2 != OPTEE_MSG_UID_2 ||
         (uint32_t)resp.a3 != OPTEE_MSG_UID_3 )
        return false;

    /* Read number of threads */
    arm_smccc_smc(OPTEE_SMC_GET_THREAD_COUNT, &resp);
    if ( resp.a0 == OPTEE_SMC_RETURN_OK )
    {
        max_optee_threads = resp.a1;
        printk(XENLOG_INFO
               "OP-TEE supports %u simultaneous threads per guest.\n",
               max_optee_threads);
    }
    else
    {
        printk(XENLOG_ERR
               "Can't read number of threads supported by OP-TEE: %x\n",
               (uint32_t)resp.a0);
        return false;
    }

    return true;
}

static int optee_domain_init(struct domain *d)
{
    struct arm_smccc_res resp;
    struct optee_domain *ctx;

    ctx = xzalloc(struct optee_domain);
    if ( !ctx )
        return -ENOMEM;

    /*
     * Inform OP-TEE about a new guest.  This is a "Fast" call in
     * terms of OP-TEE. This basically means that it can't be
     * preempted, because there is no thread allocated for it in
     * OP-TEE. No blocking calls can be issued and interrupts are
     * disabled.
     *
     * a7 should be 0, so we can't skip last 6 parameters of arm_smccc_smc()
     */
    arm_smccc_smc(OPTEE_SMC_VM_CREATED, OPTEE_CLIENT_ID(d), 0, 0, 0, 0, 0, 0,
                  &resp);
    if ( resp.a0 != OPTEE_SMC_RETURN_OK )
    {
        printk(XENLOG_WARNING "%pd: Unable to create OPTEE client: rc = 0x%X\n",
               d, (uint32_t)resp.a0);

        xfree(ctx);

        return -ENODEV;
    }

    INIT_LIST_HEAD(&ctx->call_list);
    INIT_LIST_HEAD(&ctx->shm_rpc_list);
    INIT_LIST_HEAD(&ctx->optee_shm_buf_list);
    atomic_set(&ctx->call_count, 0);
    atomic_set(&ctx->optee_shm_buf_pages, 0);
    spin_lock_init(&ctx->lock);

    d->arch.tee = ctx;

    return 0;
}

static uint64_t regpair_to_uint64(register_t reg0, register_t reg1)
{
    return ((uint64_t)reg0 << 32) | (uint32_t)reg1;
}

static void uint64_to_regpair(register_t *reg0, register_t *reg1, uint64_t val)
{
    *reg0 = val >> 32;
    *reg1 = (uint32_t)val;
}

static struct page_info *get_domain_ram_page(gfn_t gfn)
{
    struct page_info *page;
    p2m_type_t t;

    page = get_page_from_gfn(current->domain, gfn_x(gfn), &t, P2M_ALLOC);
    if ( !page || t != p2m_ram_rw )
    {
        if ( page )
            put_page(page);

        return NULL;
    }

    return page;
}

static struct optee_std_call *allocate_std_call(struct optee_domain *ctx)
{
    struct optee_std_call *call;
    int count;

    /*
     * Make sure that guest does not execute more than max_optee_threads.
     * This also indirectly limits number of RPC SHM buffers, because OP-TEE
     * allocates one such buffer per standard call.
     */
    count = atomic_add_unless(&ctx->call_count, 1, max_optee_threads);
    if ( count == max_optee_threads )
        return ERR_PTR(-ENOSPC);

    call = xzalloc(struct optee_std_call);
    if ( !call )
    {
        atomic_dec(&ctx->call_count);
        return ERR_PTR(-ENOMEM);
    }

    call->optee_thread_id = -1;
    call->in_flight = true;

    spin_lock(&ctx->lock);
    list_add_tail(&call->list, &ctx->call_list);
    spin_unlock(&ctx->lock);

    return call;
}

static void free_std_call(struct optee_domain *ctx,
                          struct optee_std_call *call)
{
    atomic_dec(&ctx->call_count);

    spin_lock(&ctx->lock);
    list_del(&call->list);
    spin_unlock(&ctx->lock);

    ASSERT(!call->in_flight);
    ASSERT(!call->xen_arg);

    if ( call->xen_arg_pg )
        free_domheap_page(call->xen_arg_pg);

    xfree(call);
}

static void map_xen_arg(struct optee_std_call *call)
{
    ASSERT(!call->xen_arg);

    call->xen_arg = __map_domain_page(call->xen_arg_pg);
}

static void unmap_xen_arg(struct optee_std_call *call)
{
    if ( !call->xen_arg )
        return;

    unmap_domain_page(call->xen_arg);
    call->xen_arg = NULL;
}

static struct optee_std_call *get_std_call(struct optee_domain *ctx,
                                           int thread_id)
{
    struct optee_std_call *call;

    spin_lock(&ctx->lock);
    list_for_each_entry( call, &ctx->call_list, list )
    {
        if ( call->optee_thread_id == thread_id )
        {
            if ( call->in_flight )
            {
                gdprintk(XENLOG_WARNING,
                         "Guest tries to execute call which is already in flight.\n");
                goto out;
            }
            call->in_flight = true;
            spin_unlock(&ctx->lock);
            map_xen_arg(call);

            return call;
        }
    }

out:
    spin_unlock(&ctx->lock);

    return NULL;
}

static void put_std_call(struct optee_domain *ctx, struct optee_std_call *call)
{
    ASSERT(call->in_flight);
    unmap_xen_arg(call);
    spin_lock(&ctx->lock);
    call->in_flight = false;
    spin_unlock(&ctx->lock);
}

static struct shm_rpc *allocate_and_pin_shm_rpc(struct optee_domain *ctx,
                                                gfn_t gfn, uint64_t cookie)
{
    struct shm_rpc *shm_rpc, *shm_rpc_tmp;

    shm_rpc = xzalloc(struct shm_rpc);
    if ( !shm_rpc )
        return ERR_PTR(-ENOMEM);

    shm_rpc->xen_arg_pg = alloc_domheap_page(current->domain, 0);
    if ( !shm_rpc->xen_arg_pg )
    {
        xfree(shm_rpc);
        return ERR_PTR(-ENOMEM);
    }

    /* This page will be shared with OP-TEE, so we need to pin it. */
    shm_rpc->guest_page = get_domain_ram_page(gfn);
    if ( !shm_rpc->guest_page )
        goto err;
    shm_rpc->gfn = gfn;

    shm_rpc->cookie = cookie;

    spin_lock(&ctx->lock);
    /* Check if there is existing SHM with the same cookie. */
    list_for_each_entry( shm_rpc_tmp, &ctx->shm_rpc_list, list )
    {
        if ( shm_rpc_tmp->cookie == cookie )
        {
            spin_unlock(&ctx->lock);
            gdprintk(XENLOG_WARNING,
                     "Guest tries to use the same RPC SHM cookie %"PRIx64"\n",
                     cookie);
            goto err;
        }
    }

    list_add_tail(&shm_rpc->list, &ctx->shm_rpc_list);
    spin_unlock(&ctx->lock);

    return shm_rpc;

err:
    free_domheap_page(shm_rpc->xen_arg_pg);

    if ( shm_rpc->guest_page )
        put_page(shm_rpc->guest_page);
    xfree(shm_rpc);

    return ERR_PTR(-EINVAL);
}

static void free_shm_rpc(struct optee_domain *ctx, uint64_t cookie)
{
    struct shm_rpc *shm_rpc;
    bool found = false;

    spin_lock(&ctx->lock);

    list_for_each_entry( shm_rpc, &ctx->shm_rpc_list, list )
    {
        if ( shm_rpc->cookie == cookie )
        {
            found = true;
            list_del(&shm_rpc->list);
            break;
        }
    }
    spin_unlock(&ctx->lock);

    if ( !found )
        return;

    free_domheap_page(shm_rpc->xen_arg_pg);

    ASSERT(shm_rpc->guest_page);
    put_page(shm_rpc->guest_page);

    xfree(shm_rpc);
}

static struct shm_rpc *find_shm_rpc(struct optee_domain *ctx, uint64_t cookie)
{
    struct shm_rpc *shm_rpc;

    spin_lock(&ctx->lock);
    list_for_each_entry( shm_rpc, &ctx->shm_rpc_list, list )
    {
        if ( shm_rpc->cookie == cookie )
        {
                spin_unlock(&ctx->lock);
                return shm_rpc;
        }
    }
    spin_unlock(&ctx->lock);

    return NULL;
}

static struct optee_shm_buf *allocate_optee_shm_buf(struct optee_domain *ctx,
                                                    uint64_t cookie,
                                                    unsigned int pages_cnt,
                                                    struct page_info *pg_list,
                                                    unsigned int pg_list_order)
{
    struct optee_shm_buf *optee_shm_buf, *optee_shm_buf_tmp;
    int old, new;
    int err_code;

    do
    {
        old = atomic_read(&ctx->optee_shm_buf_pages);
        new = old + pages_cnt;
        if ( new >= MAX_TOTAL_SMH_BUF_PG )
            return ERR_PTR(-ENOMEM);
    }
    while ( unlikely(old != atomic_cmpxchg(&ctx->optee_shm_buf_pages,
                                           old, new)) );

    /*
     * TODO: Guest can try to register many small buffers, thus, forcing
     * XEN to allocate context for every buffer. Probably we need to
     * limit not only total number of pages pinned but also number
     * of buffer objects.
     */
    optee_shm_buf = xzalloc_bytes(sizeof(struct optee_shm_buf) +
                                  pages_cnt * sizeof(struct page *));
    if ( !optee_shm_buf )
    {
        err_code = -ENOMEM;
        goto err;
    }

    optee_shm_buf->cookie = cookie;
    optee_shm_buf->pg_list = pg_list;
    optee_shm_buf->pg_list_order = pg_list_order;

    spin_lock(&ctx->lock);
    /* Check if there is already SHM with the same cookie */
    list_for_each_entry( optee_shm_buf_tmp, &ctx->optee_shm_buf_list, list )
    {
        if ( optee_shm_buf_tmp->cookie == cookie )
        {
            spin_unlock(&ctx->lock);
            gdprintk(XENLOG_WARNING,
                     "Guest tries to use the same SHM buffer cookie %"PRIx64"\n",
                     cookie);
            err_code = -EINVAL;
            goto err;
        }
    }

    list_add_tail(&optee_shm_buf->list, &ctx->optee_shm_buf_list);
    spin_unlock(&ctx->lock);

    return optee_shm_buf;

err:
    xfree(optee_shm_buf);
    atomic_sub(pages_cnt, &ctx->optee_shm_buf_pages);

    return ERR_PTR(err_code);
}

static void free_pg_list(struct optee_shm_buf *optee_shm_buf)
{
    if ( optee_shm_buf->pg_list )
    {
        free_domheap_pages(optee_shm_buf->pg_list,
                           optee_shm_buf->pg_list_order);
        optee_shm_buf->pg_list = NULL;
    }
}

static void free_optee_shm_buf(struct optee_domain *ctx, uint64_t cookie)
{
    struct optee_shm_buf *optee_shm_buf;
    unsigned int i;
    bool found = false;

    spin_lock(&ctx->lock);
    list_for_each_entry( optee_shm_buf, &ctx->optee_shm_buf_list, list )
    {
        if ( optee_shm_buf->cookie == cookie )
        {
            found = true;
            list_del(&optee_shm_buf->list);
            break;
        }
    }
    spin_unlock(&ctx->lock);

    if ( !found )
        return;

    for ( i = 0; i < optee_shm_buf->page_cnt; i++ )
        if ( optee_shm_buf->pages[i] )
            put_page(optee_shm_buf->pages[i]);

    free_pg_list(optee_shm_buf);

    atomic_sub(optee_shm_buf->page_cnt, &ctx->optee_shm_buf_pages);

    xfree(optee_shm_buf);
}

static void free_optee_shm_buf_pg_list(struct optee_domain *ctx,
                                       uint64_t cookie)
{
    struct optee_shm_buf *optee_shm_buf;
    bool found = false;

    spin_lock(&ctx->lock);
    list_for_each_entry( optee_shm_buf, &ctx->optee_shm_buf_list, list )
    {
        if ( optee_shm_buf->cookie == cookie )
        {
            found = true;
            break;
        }
    }
    spin_unlock(&ctx->lock);

    if ( found )
        free_pg_list(optee_shm_buf);
    else
        gdprintk(XENLOG_ERR,
                 "Can't find pagelist for SHM buffer with cookie %"PRIx64" to free it\n",
                 cookie);
}

static int optee_relinquish_resources(struct domain *d)
{
    struct arm_smccc_res resp;
    struct optee_std_call *call, *call_tmp;
    struct shm_rpc *shm_rpc, *shm_rpc_tmp;
    struct optee_shm_buf *optee_shm_buf, *optee_shm_buf_tmp;
    struct optee_domain *ctx = d->arch.tee;

    if ( !ctx )
        return 0;

    /*
     * We need to free up to max_optee_threads calls. Usually, this is
     * no more than 8-16 calls. But it depends on OP-TEE configuration
     * (CFG_NUM_THREADS option).
     */
    list_for_each_entry_safe( call, call_tmp, &ctx->call_list, list )
        free_std_call(ctx, call);

    if ( hypercall_preempt_check() )
        return -ERESTART;

    /*
     * Number of this buffers also depends on max_optee_threads, so
     * check the comment above.
     */
    list_for_each_entry_safe( shm_rpc, shm_rpc_tmp, &ctx->shm_rpc_list, list )
        free_shm_rpc(ctx, shm_rpc->cookie);

    if ( hypercall_preempt_check() )
        return -ERESTART;

    /*
     * TODO: Guest can pin up to MAX_TOTAL_SMH_BUF_PG pages and all of
     * them will be put in this loop. It is worth considering to
     * check for preemption inside the loop.
     */
    list_for_each_entry_safe( optee_shm_buf, optee_shm_buf_tmp,
                              &ctx->optee_shm_buf_list, list )
        free_optee_shm_buf(ctx, optee_shm_buf->cookie);

    if ( hypercall_preempt_check() )
        return -ERESTART;
    /*
     * Inform OP-TEE that domain is shutting down. This is
     * also a fast SMC call, like OPTEE_SMC_VM_CREATED, so
     * it is also non-preemptible.
     * At this time all domain VCPUs should be stopped. OP-TEE
     * relies on this.
     *
     * a7 should be 0, so we can't skip last 6 parameters of arm_smccc_smc()
     */
    arm_smccc_smc(OPTEE_SMC_VM_DESTROYED, OPTEE_CLIENT_ID(d), 0, 0, 0, 0, 0, 0,
                  &resp);

    ASSERT(!spin_is_locked(&ctx->lock));
    ASSERT(!atomic_read(&ctx->call_count));
    ASSERT(!atomic_read(&ctx->optee_shm_buf_pages));
    ASSERT(list_empty(&ctx->shm_rpc_list));

    XFREE(d->arch.tee);

    return 0;
}

#define PAGELIST_ENTRIES_PER_PAGE                       \
    ((OPTEE_MSG_NONCONTIG_PAGE_SIZE / sizeof(u64)) - 1)

static size_t get_pages_list_size(size_t num_entries)
{
    int pages = DIV_ROUND_UP(num_entries, PAGELIST_ENTRIES_PER_PAGE);

    return pages * OPTEE_MSG_NONCONTIG_PAGE_SIZE;
}

static int translate_noncontig(struct optee_domain *ctx,
                               struct optee_std_call *call,
                               struct optee_msg_param *param)
{
    uint64_t size;
    unsigned int offset;
    unsigned int pg_count;
    unsigned int order;
    unsigned int idx = 0;
    gfn_t gfn;
    struct page_info *guest_pg, *xen_pgs;
    struct optee_shm_buf *optee_shm_buf;
    /*
     * This is memory layout for page list. Basically list consists of 4k pages,
     * every page store 511 page addresses of user buffer and page address of
     * the next page of list.
     *
     * Refer to OPTEE_MSG_ATTR_NONCONTIG description in optee_msg.h for details.
     */
    struct {
        uint64_t pages_list[PAGELIST_ENTRIES_PER_PAGE];
        uint64_t next_page_data;
    } *guest_data, *xen_data;

    /* Offset of user buffer withing OPTEE_MSG_NONCONTIG_PAGE_SIZE-sized page */
    offset = param->u.tmem.buf_ptr & (OPTEE_MSG_NONCONTIG_PAGE_SIZE - 1);

    /* Size of the user buffer in bytes */
    size = ROUNDUP(param->u.tmem.size + offset, OPTEE_MSG_NONCONTIG_PAGE_SIZE);

    pg_count = DIV_ROUND_UP(size, OPTEE_MSG_NONCONTIG_PAGE_SIZE);
    order = get_order_from_bytes(get_pages_list_size(pg_count));

    /*
     * In the worst case we will want to allocate 33 pages, which is
     * MAX_TOTAL_SMH_BUF_PG/511 rounded up. This gives order 6 or at
     * most 64 pages allocated. This buffer will be freed right after
     * the end of the call and there can be no more than
     * max_optee_threads calls simultaneously. So in the worst case
     * guest can trick us to allocate 64 * max_optee_threads pages in
     * total.
     */
    xen_pgs = alloc_domheap_pages(current->domain, order, 0);
    if ( !xen_pgs )
        return -ENOMEM;

    optee_shm_buf = allocate_optee_shm_buf(ctx, param->u.tmem.shm_ref,
                                           pg_count, xen_pgs, order);
    if ( IS_ERR(optee_shm_buf) )
        return PTR_ERR(optee_shm_buf);

    gfn = gaddr_to_gfn(param->u.tmem.buf_ptr &
                       ~(OPTEE_MSG_NONCONTIG_PAGE_SIZE - 1));

    /*
     * We are initializing guest_pg, guest_data and xen_data with NULL
     * to make GCC 4.8 happy, as it can't infer that those variables
     * will be initialized with correct values in the loop below.
     *
     * This silences old GCC, but can lead to NULL dereference, in
     * case of programmer's mistake. To minimize chance of this, we
     * are initializing those variables there, instead of doing this
     * at beginning of the function.
     */
    guest_pg = NULL;
    xen_data = NULL;
    guest_data = NULL;
    while ( pg_count )
    {
        struct page_info *page;

        if ( idx == 0 )
        {
            guest_pg = get_domain_ram_page(gfn);
            if ( !guest_pg )
                return -EINVAL;

            guest_data = __map_domain_page(guest_pg);
            xen_data = __map_domain_page(xen_pgs);
        }

        /*
         * TODO: That function can pin up to 64MB of guest memory by
         * calling lookup_and_pin_guest_ram_addr() 16384 times
         * (assuming that PAGE_SIZE equals to 4096).
         * This should be addressed before declaring OP-TEE security
         * supported.
         */
        BUILD_BUG_ON(PAGE_SIZE != 4096);
        page = get_domain_ram_page(gaddr_to_gfn(guest_data->pages_list[idx]));
        if ( !page )
            goto err_unmap;

        optee_shm_buf->pages[optee_shm_buf->page_cnt++] = page;
        xen_data->pages_list[idx] = page_to_maddr(page);
        idx++;

        if ( idx == PAGELIST_ENTRIES_PER_PAGE )
        {
            /* Roll over to the next page */
            xen_data->next_page_data = page_to_maddr(xen_pgs + 1);
            xen_pgs++;

            gfn = gaddr_to_gfn(guest_data->next_page_data);

            unmap_domain_page(xen_data);
            unmap_domain_page(guest_data);
            put_page(guest_pg);

            idx = 0;
        }
        pg_count--;
    }

    if ( idx )
    {
        unmap_domain_page(guest_data);
        unmap_domain_page(xen_data);
        put_page(guest_pg);
    }
    param->u.tmem.buf_ptr = page_to_maddr(optee_shm_buf->pg_list) | offset;

    return 0;

err_unmap:
    unmap_domain_page(guest_data);
    unmap_domain_page(xen_data);
    put_page(guest_pg);
    free_optee_shm_buf(ctx, optee_shm_buf->cookie);

    return -EINVAL;
}

static int translate_params(struct optee_domain *ctx,
                            struct optee_std_call *call)
{
    unsigned int i;
    uint32_t attr;
    int ret = 0;

    for ( i = 0; i < call->xen_arg->num_params; i++ )
    {
        attr = call->xen_arg->params[i].attr;

        switch ( attr & OPTEE_MSG_ATTR_TYPE_MASK )
        {
        case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
        case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
            if ( attr & OPTEE_MSG_ATTR_NONCONTIG )
            {
                ret = translate_noncontig(ctx, call, call->xen_arg->params + i);
                if ( ret )
                    goto out;
            }
            else
            {
                gdprintk(XENLOG_WARNING, "Guest tries to use old tmem arg\n");
                ret = -EINVAL;
                goto out;
            }
            break;
        case OPTEE_MSG_ATTR_TYPE_NONE:
        case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
        case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
        case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
        case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
            continue;
        }
    }

out:
    if ( ret )
    {
        call->xen_arg->ret_origin = TEEC_ORIGIN_COMMS;
        if ( ret == -ENOMEM )
            call->xen_arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
        else
            call->xen_arg->ret = TEEC_ERROR_BAD_PARAMETERS;
    }

    return ret;
}

/*
 * Copy command buffer into domheap memory to:
 * 1) Hide translated addresses from guest
 * 2) Make sure that guest wouldn't change data in command buffer during call
 */
static bool copy_std_request(struct cpu_user_regs *regs,
                             struct optee_std_call *call)
{
    call->guest_arg_ipa = regpair_to_uint64(get_user_reg(regs, 1),
                                            get_user_reg(regs, 2));

    /*
     * Command buffer should start at page boundary.
     * This is OP-TEE ABI requirement.
     */
    if ( call->guest_arg_ipa & (OPTEE_MSG_NONCONTIG_PAGE_SIZE - 1) )
    {
        set_user_reg(regs, 0, OPTEE_SMC_RETURN_EBADADDR);
        return false;
    }

    BUILD_BUG_ON(OPTEE_MSG_NONCONTIG_PAGE_SIZE > PAGE_SIZE);

    call->xen_arg_pg = alloc_domheap_page(current->domain, 0);
    if ( !call->xen_arg_pg )
    {
        set_user_reg(regs, 0, OPTEE_SMC_RETURN_ENOMEM);
        return false;
    }

    map_xen_arg(call);

    if ( access_guest_memory_by_ipa(current->domain, call->guest_arg_ipa,
                                    call->xen_arg,
                                    OPTEE_MSG_NONCONTIG_PAGE_SIZE, false) )
    {
        set_user_reg(regs, 0, OPTEE_SMC_RETURN_EBADADDR);
        return false;
    }

    return true;
}

/*
 * Copy result of completed request back to guest's buffer.
 * We are copying only values that subjected to change to minimize
 * possible information leak.
 *
 * Because there can be multiple RPCs during standard call, and guest
 * is not obligated to return from RPC immediately, there can be
 * arbitrary time span between calling copy_std_request() and
 * copy_std_request(). So we need to validate guest's command buffer
 * again.
 */
static void copy_std_request_back(struct optee_domain *ctx,
                                  struct cpu_user_regs *regs,
                                  struct optee_std_call *call)
{
    struct optee_msg_arg *guest_arg;
    struct page_info *page;
    unsigned int i;
    uint32_t attr;

    page = get_domain_ram_page(gaddr_to_gfn(call->guest_arg_ipa));
    if ( !page )
    {
        /*
         * Guest did something to own command buffer during the call.
         * Now we even can't write error code to the command
         * buffer. Let's try to return generic error via
         * register. Problem is that OP-TEE does not know that guest
         * didn't received valid response. But at least guest will
         * know that something bad happened.
         */
        set_user_reg(regs, 0, OPTEE_SMC_RETURN_EBADADDR);

        return;
    }

    guest_arg = __map_domain_page(page);

    guest_arg->ret = call->xen_arg->ret;
    guest_arg->ret_origin = call->xen_arg->ret_origin;
    guest_arg->session = call->xen_arg->session;

    for ( i = 0; i < call->xen_arg->num_params; i++ )
    {
        attr = call->xen_arg->params[i].attr;

        switch ( attr & OPTEE_MSG_ATTR_TYPE_MASK )
        {
        case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
            guest_arg->params[i].u.tmem.size =
                call->xen_arg->params[i].u.tmem.size;
            continue;
        case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
            guest_arg->params[i].u.rmem.size =
                call->xen_arg->params[i].u.rmem.size;
            continue;
        case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
            guest_arg->params[i].u.value.a =
                call->xen_arg->params[i].u.value.a;
            guest_arg->params[i].u.value.b =
                call->xen_arg->params[i].u.value.b;
            guest_arg->params[i].u.value.c =
                call->xen_arg->params[i].u.value.c;
            continue;
        case OPTEE_MSG_ATTR_TYPE_NONE:
        case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
        case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
            continue;
        }
    }

    unmap_domain_page(guest_arg);
    put_page(page);
}


static void free_shm_buffers(struct optee_domain *ctx,
                             struct optee_msg_arg *arg)
{
    unsigned int i;

    for ( i = 0; i < arg->num_params; i ++ )
    {
        switch ( arg->params[i].attr & OPTEE_MSG_ATTR_TYPE_MASK )
        {
        case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
        case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
            free_optee_shm_buf(ctx, arg->params[i].u.tmem.shm_ref);
            break;
        default:
            break;
        }
    }
}

/* Handle RPC return from OP-TEE */
static int handle_rpc_return(struct optee_domain *ctx,
                             struct arm_smccc_res *res,
                             struct cpu_user_regs *regs,
                             struct optee_std_call *call)
{
    int ret = 0;

    call->rpc_op = OPTEE_SMC_RETURN_GET_RPC_FUNC(res->a0);
    call->rpc_params[0] = res->a1;
    call->rpc_params[1] = res->a2;
    call->optee_thread_id = res->a3;

    set_user_reg(regs, 0, res->a0);
    set_user_reg(regs, 1, res->a1);
    set_user_reg(regs, 2, res->a2);
    set_user_reg(regs, 3, res->a3);

    if ( call->rpc_op == OPTEE_SMC_RPC_FUNC_CMD )
    {
        /* Copy RPC request from shadowed buffer to guest */
        uint64_t cookie = regpair_to_uint64(get_user_reg(regs, 1),
                                            get_user_reg(regs, 2));
        struct shm_rpc *shm_rpc = find_shm_rpc(ctx, cookie);

        if ( !shm_rpc )
        {
            /*
             * This is a very exceptional situation: OP-TEE used
             * cookie for unknown shared buffer. Something is very
             * wrong there. We can't even report error back to OP-TEE,
             * because there is no buffer where we can write return
             * code. Luckily, OP-TEE sets default error code into that
             * buffer before the call, expecting that normal world
             * will overwrite it with actual result. So we can just
             * continue the call.
             */
            gprintk(XENLOG_ERR, "Can't find SHM-RPC with cookie %"PRIx64"\n",
                    cookie);

            return -ERESTART;
        }

        shm_rpc->xen_arg = __map_domain_page(shm_rpc->xen_arg_pg);

        if ( access_guest_memory_by_ipa(current->domain,
                        gfn_to_gaddr(shm_rpc->gfn),
                        shm_rpc->xen_arg,
                        OPTEE_MSG_GET_ARG_SIZE(shm_rpc->xen_arg->num_params),
                        true) )
        {
            /*
             * We were unable to propagate request to guest, so let's return
             * back to OP-TEE.
             */
            shm_rpc->xen_arg->ret = TEEC_ERROR_GENERIC;
            ret = -ERESTART;
        }

        unmap_domain_page(shm_rpc->xen_arg);
    }

    return ret;
}

/*
 * (Re)start standard call. This function will be called in two cases:
 * 1. Guest initiates new standard call
 * 2. Guest finished RPC handling and asks OP-TEE to resume the call
 *
 * In any case OP-TEE can either complete call or issue another RPC.
 * If this is RPC - we need to store call context and return back to guest.
 * If call is complete - we need to return results with copy_std_request_back()
 * and then we will destroy the call context as it is not needed anymore.
 *
 * In some rare cases we can't propagate RPC request back to guest, so we will
 * restart the call, telling OP-TEE that request had failed.
 *
 * Shared buffers should be handled in a special way.
 */
static void do_call_with_arg(struct optee_domain *ctx,
                             struct optee_std_call *call,
                             struct cpu_user_regs *regs,
                             register_t a0, register_t a1, register_t a2,
                             register_t a3, register_t a4, register_t a5)
{
    struct arm_smccc_res res;

    arm_smccc_smc(a0, a1, a2, a3, a4, a5, 0, OPTEE_CLIENT_ID(current->domain),
                  &res);

    if ( OPTEE_SMC_RETURN_IS_RPC(res.a0) )
    {
        while ( handle_rpc_return(ctx, &res, regs, call)  == -ERESTART )
        {
            arm_smccc_smc(res.a0, res.a1, res.a2, res.a3, 0, 0, 0,
                          OPTEE_CLIENT_ID(current->domain), &res);

            if ( !OPTEE_SMC_RETURN_IS_RPC(res.a0) )
                break;

        }

        put_std_call(ctx, call);

        return;
    }

    copy_std_request_back(ctx, regs, call);
    set_user_reg(regs, 0, res.a0);

    switch ( call->xen_arg->cmd )
    {
    case OPTEE_MSG_CMD_REGISTER_SHM:
        if ( call->xen_arg->ret == 0 )
            /* OP-TEE registered buffer, we don't need pg_list anymore */
            free_optee_shm_buf_pg_list(ctx,
                                       call->xen_arg->params[0].u.tmem.shm_ref);
        else
            /* OP-TEE failed to register buffer, we need to unpin guest pages */
            free_optee_shm_buf(ctx, call->xen_arg->params[0].u.tmem.shm_ref);
        break;
    case OPTEE_MSG_CMD_UNREGISTER_SHM:
        if ( call->xen_arg->ret == 0 )
            /* Now we can unpin guest pages */
            free_optee_shm_buf(ctx, call->xen_arg->params[0].u.rmem.shm_ref);
        break;
    default:
        /* Free any temporary shared buffers */
        free_shm_buffers(ctx, call->xen_arg);
    }

    put_std_call(ctx, call);
    free_std_call(ctx, call);
}

/*
 * Standard call handling. This is the main type of the call which
 * makes OP-TEE useful. Most of the other calls type are utility
 * calls, while standard calls are needed to interact with Trusted
 * Applications which are running inside the OP-TEE.
 *
 * All arguments for this type of call are passed in the command
 * buffer in the guest memory. We will copy this buffer into
 * own shadow buffer and provide the copy to OP-TEE.
 *
 * This call is preemptible. OP-TEE will return from the call if there
 * is an interrupt request pending. Also, OP-TEE will interrupt the
 * call if it needs some service from guest. In both cases it will
 * issue RPC, which is processed by handle_rpc_return() function.
 */
static void handle_std_call(struct optee_domain *ctx,
                            struct cpu_user_regs *regs)
{
    register_t a1, a2;
    paddr_t xen_addr;
    size_t arg_size;
    struct optee_std_call *call = allocate_std_call(ctx);

    if ( IS_ERR(call) )
    {
        if ( PTR_ERR(call) == -ENOMEM )
            set_user_reg(regs, 0, OPTEE_SMC_RETURN_ENOMEM);
        else
            set_user_reg(regs, 0, OPTEE_SMC_RETURN_ETHREAD_LIMIT);

        return;
    }

    if ( !copy_std_request(regs, call) )
        goto err;

    arg_size = OPTEE_MSG_GET_ARG_SIZE(call->xen_arg->num_params);
    if ( arg_size > OPTEE_MSG_NONCONTIG_PAGE_SIZE )
    {
        call->xen_arg->ret = TEEC_ERROR_BAD_PARAMETERS;
        call->xen_arg->ret_origin = TEEC_ORIGIN_COMMS;
        /* Make sure that copy_std_request_back() will stay within the buffer */
        call->xen_arg->num_params = 0;

        copy_std_request_back(ctx, regs, call);

        goto err;
    }

    switch ( call->xen_arg->cmd )
    {
    case OPTEE_MSG_CMD_OPEN_SESSION:
    case OPTEE_MSG_CMD_CLOSE_SESSION:
    case OPTEE_MSG_CMD_INVOKE_COMMAND:
    case OPTEE_MSG_CMD_CANCEL:
    case OPTEE_MSG_CMD_REGISTER_SHM:
    case OPTEE_MSG_CMD_UNREGISTER_SHM:
        if( translate_params(ctx, call) )
        {
            /*
             * translate_params() sets xen_arg->ret value to non-zero.
             * So, technically, SMC was successful, but there was an error
             * during handling standard call encapsulated into this SMC.
             */
            copy_std_request_back(ctx, regs, call);
            set_user_reg(regs, 0, OPTEE_SMC_RETURN_OK);
            goto err;
        }

        xen_addr = page_to_maddr(call->xen_arg_pg);
        uint64_to_regpair(&a1, &a2, xen_addr);

        do_call_with_arg(ctx, call, regs, OPTEE_SMC_CALL_WITH_ARG, a1, a2,
                         OPTEE_SMC_SHM_CACHED, 0, 0);
        return;
    default:
        set_user_reg(regs, 0, OPTEE_SMC_RETURN_EBADCMD);
        break;
    }

err:
    put_std_call(ctx, call);
    free_std_call(ctx, call);

    return;
}

/*
 * This function is called when guest is finished processing RPC
 * request from OP-TEE and wished to resume the interrupted standard
 * call.
 */
static void handle_rpc_cmd_alloc(struct optee_domain *ctx,
                                 struct cpu_user_regs *regs,
                                 struct optee_std_call *call,
                                 struct shm_rpc *shm_rpc)
{
    if ( shm_rpc->xen_arg->ret || shm_rpc->xen_arg->num_params != 1 )
        return;

    if ( shm_rpc->xen_arg->params[0].attr != (OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT |
                                              OPTEE_MSG_ATTR_NONCONTIG) )
    {
        gdprintk(XENLOG_WARNING,
                 "Invalid attrs for shared mem buffer: %"PRIx64"\n",
                 shm_rpc->xen_arg->params[0].attr);
        return;
    }

    /* Free pg list for buffer */
    if ( call->rpc_data_cookie )
        free_optee_shm_buf_pg_list(ctx, call->rpc_data_cookie);

    if ( !translate_noncontig(ctx, call, &shm_rpc->xen_arg->params[0]) )
    {
        call->rpc_data_cookie =
            shm_rpc->xen_arg->params[0].u.tmem.shm_ref;
    }
    else
    {
        call->rpc_data_cookie = 0;
        /*
         * Okay, so there was problem with guest's buffer and we need
         * to tell about this to OP-TEE.
         */
        shm_rpc->xen_arg->ret = TEEC_ERROR_GENERIC;
        shm_rpc->xen_arg->num_params = 0;
        /*
         * TODO: With current implementation, OP-TEE will not issue
         * RPC to free this buffer. Guest and OP-TEE will be out of
         * sync: guest believes that it provided buffer to OP-TEE,
         * while OP-TEE thinks of opposite. Ideally, we need to
         * emulate RPC with OPTEE_MSG_RPC_CMD_SHM_FREE command.
         */
        gprintk(XENLOG_WARNING,
                "translate_noncontig() failed, OP-TEE/guest state is out of sync.\n");
    }
}

static void handle_rpc_cmd(struct optee_domain *ctx, struct cpu_user_regs *regs,
                           struct optee_std_call *call)
{
    struct shm_rpc *shm_rpc;
    uint64_t cookie;
    size_t arg_size;

    cookie = regpair_to_uint64(get_user_reg(regs, 1),
                               get_user_reg(regs, 2));

    shm_rpc = find_shm_rpc(ctx, cookie);

    if ( !shm_rpc )
    {
        gdprintk(XENLOG_ERR, "Can't find SHM-RPC with cookie %"PRIx64"\n",
                 cookie);
        return;
    }

    shm_rpc->xen_arg = __map_domain_page(shm_rpc->xen_arg_pg);

    /* First, copy only header to read number of arguments */
    if ( access_guest_memory_by_ipa(current->domain,
                                    gfn_to_gaddr(shm_rpc->gfn),
                                    shm_rpc->xen_arg,
                                    sizeof(struct optee_msg_arg),
                                    false) )
    {
        shm_rpc->xen_arg->ret = TEEC_ERROR_GENERIC;
        goto out;
    }

    arg_size = OPTEE_MSG_GET_ARG_SIZE(shm_rpc->xen_arg->num_params);
    if ( arg_size > OPTEE_MSG_NONCONTIG_PAGE_SIZE )
    {
        shm_rpc->xen_arg->ret = TEEC_ERROR_GENERIC;
        goto out;
    }

    /* Read the whole command structure */
    if ( access_guest_memory_by_ipa(current->domain, gfn_to_gaddr(shm_rpc->gfn),
                                    shm_rpc->xen_arg, arg_size, false) )
    {
        shm_rpc->xen_arg->ret = TEEC_ERROR_GENERIC;
        goto out;
    }

    switch (shm_rpc->xen_arg->cmd)
    {
    case OPTEE_RPC_CMD_GET_TIME:
    case OPTEE_RPC_CMD_WAIT_QUEUE:
    case OPTEE_RPC_CMD_SUSPEND:
        break;
    case OPTEE_RPC_CMD_SHM_ALLOC:
        handle_rpc_cmd_alloc(ctx, regs, call, shm_rpc);
        break;
    case OPTEE_RPC_CMD_SHM_FREE:
        free_optee_shm_buf(ctx, shm_rpc->xen_arg->params[0].u.value.b);
        if ( call->rpc_data_cookie == shm_rpc->xen_arg->params[0].u.value.b )
            call->rpc_data_cookie = 0;
        break;
    default:
        break;
    }

out:
    unmap_domain_page(shm_rpc->xen_arg);

    do_call_with_arg(ctx, call, regs, OPTEE_SMC_CALL_RETURN_FROM_RPC, 0, 0,
                     get_user_reg(regs, 3), 0, 0);

}

static void handle_rpc_func_alloc(struct optee_domain *ctx,
                                  struct cpu_user_regs *regs,
                                  struct optee_std_call *call)
{
    struct shm_rpc *shm_rpc;
    register_t r1, r2;
    paddr_t ptr = regpair_to_uint64(get_user_reg(regs, 1),
                                    get_user_reg(regs, 2));
    uint64_t cookie = regpair_to_uint64(get_user_reg(regs, 4),
                                        get_user_reg(regs, 5));

    if ( ptr & (OPTEE_MSG_NONCONTIG_PAGE_SIZE - 1) )
    {
        gdprintk(XENLOG_WARNING, "Domain returned invalid RPC command buffer\n");
        /*
         * OP-TEE is waiting for a response to the RPC. We can't just
         * return error to the guest. We need to provide some invalid
         * value to OP-TEE, so it can handle error on its side.
         */
        ptr = 0;
        goto out;
    }

    shm_rpc = allocate_and_pin_shm_rpc(ctx, gaddr_to_gfn(ptr), cookie);
    if ( IS_ERR(shm_rpc) )
    {
        gdprintk(XENLOG_WARNING, "Failed to allocate shm_rpc object: %ld\n",
                 PTR_ERR(shm_rpc));
        ptr = 0;
    }
    else
        ptr = page_to_maddr(shm_rpc->xen_arg_pg);

out:
    uint64_to_regpair(&r1, &r2, ptr);

    do_call_with_arg(ctx, call, regs, OPTEE_SMC_CALL_RETURN_FROM_RPC, r1, r2,
                     get_user_reg(regs, 3),
                     get_user_reg(regs, 4),
                     get_user_reg(regs, 5));
}

static void handle_rpc(struct optee_domain *ctx, struct cpu_user_regs *regs)
{
    struct optee_std_call *call;
    int optee_thread_id = get_user_reg(regs, 3);

    call = get_std_call(ctx, optee_thread_id);

    if ( !call )
    {
        set_user_reg(regs, 0, OPTEE_SMC_RETURN_ERESUME);
        return;
    }

    /*
     * This is to prevent race between new call with the same thread id.
     * OP-TEE can reuse thread id right after it finished handling the call,
     * before XEN had chance to free old call context.
     */
    call->optee_thread_id = -1;

    switch ( call->rpc_op )
    {
    case OPTEE_SMC_RPC_FUNC_ALLOC:
        handle_rpc_func_alloc(ctx, regs, call);
        return;
    case OPTEE_SMC_RPC_FUNC_FREE:
    {
        uint64_t cookie = regpair_to_uint64(call->rpc_params[0],
                                            call->rpc_params[1]);
        free_shm_rpc(ctx, cookie);
        break;
    }
    case OPTEE_SMC_RPC_FUNC_FOREIGN_INTR:
        break;
    case OPTEE_SMC_RPC_FUNC_CMD:
        handle_rpc_cmd(ctx, regs, call);
        return;
    }

    do_call_with_arg(ctx, call, regs, OPTEE_SMC_CALL_RETURN_FROM_RPC,
                     call->rpc_params[0], call->rpc_params[1],
                     optee_thread_id, 0, 0);
    return;
}

static void handle_exchange_capabilities(struct cpu_user_regs *regs)
{
    struct arm_smccc_res resp;
    uint32_t caps;

    /* Filter out unknown guest caps */
    caps = get_user_reg(regs, 1);
    caps &= OPTEE_KNOWN_NSEC_CAPS;

    arm_smccc_smc(OPTEE_SMC_EXCHANGE_CAPABILITIES, caps, 0, 0, 0, 0, 0,
                  OPTEE_CLIENT_ID(current->domain), &resp);
    if ( resp.a0 != OPTEE_SMC_RETURN_OK ) {
        set_user_reg(regs, 0, resp.a0);
        return;
    }

    caps = resp.a1;

    /* Filter out unknown OP-TEE caps */
    caps &= OPTEE_KNOWN_SEC_CAPS;

    /* Drop static SHM_RPC cap */
    caps &= ~OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM;

    /* Don't allow guests to work without dynamic SHM */
    if ( !(caps & OPTEE_SMC_SEC_CAP_DYNAMIC_SHM) )
    {
        set_user_reg(regs, 0, OPTEE_SMC_RETURN_ENOTAVAIL);
        return;
    }

    set_user_reg(regs, 0, OPTEE_SMC_RETURN_OK);
    set_user_reg(regs, 1, caps);
}

static bool optee_handle_call(struct cpu_user_regs *regs)
{
    struct arm_smccc_res resp;
    struct optee_domain *ctx = current->domain->arch.tee;

    if ( !ctx )
        return false;

    switch ( get_user_reg(regs, 0) )
    {
    case OPTEE_SMC_CALLS_COUNT:
        set_user_reg(regs, 0, OPTEE_MEDIATOR_SMC_COUNT);
        return true;

    case OPTEE_SMC_CALLS_UID:
        arm_smccc_smc(OPTEE_SMC_CALLS_UID, 0, 0, 0, 0, 0, 0,
                      OPTEE_CLIENT_ID(current->domain), &resp);
        set_user_reg(regs, 0, resp.a0);
        set_user_reg(regs, 1, resp.a1);
        set_user_reg(regs, 2, resp.a2);
        set_user_reg(regs, 3, resp.a3);
        return true;

    case OPTEE_SMC_CALLS_REVISION:
        arm_smccc_smc(OPTEE_SMC_CALLS_REVISION, 0, 0, 0, 0, 0, 0,
                      OPTEE_CLIENT_ID(current->domain), &resp);
        set_user_reg(regs, 0, resp.a0);
        set_user_reg(regs, 1, resp.a1);
        return true;

    case OPTEE_SMC_CALL_GET_OS_UUID:
        arm_smccc_smc(OPTEE_SMC_CALL_GET_OS_UUID, 0, 0, 0, 0, 0, 0,
                      OPTEE_CLIENT_ID(current->domain),&resp);
        set_user_reg(regs, 0, resp.a0);
        set_user_reg(regs, 1, resp.a1);
        set_user_reg(regs, 2, resp.a2);
        set_user_reg(regs, 3, resp.a3);
        return true;

    case OPTEE_SMC_CALL_GET_OS_REVISION:
        arm_smccc_smc(OPTEE_SMC_CALL_GET_OS_REVISION, 0, 0, 0, 0, 0, 0,
                      OPTEE_CLIENT_ID(current->domain), &resp);
        set_user_reg(regs, 0, resp.a0);
        set_user_reg(regs, 1, resp.a1);
        return true;

    case OPTEE_SMC_ENABLE_SHM_CACHE:
        arm_smccc_smc(OPTEE_SMC_ENABLE_SHM_CACHE, 0, 0, 0, 0, 0, 0,
                      OPTEE_CLIENT_ID(current->domain), &resp);
        set_user_reg(regs, 0, resp.a0);
        return true;

    case OPTEE_SMC_DISABLE_SHM_CACHE:
        arm_smccc_smc(OPTEE_SMC_ENABLE_SHM_CACHE, 0, 0, 0, 0, 0, 0,
                      OPTEE_CLIENT_ID(current->domain), &resp);
        set_user_reg(regs, 0, resp.a0);
        if ( resp.a0 == OPTEE_SMC_RETURN_OK ) {
            free_shm_rpc(ctx,  regpair_to_uint64(resp.a1, resp.a2));
            set_user_reg(regs, 1, resp.a1);
            set_user_reg(regs, 2, resp.a2);
        }
        return true;

    case OPTEE_SMC_GET_SHM_CONFIG:
        /* No static SHM available for guests */
        set_user_reg(regs, 0, OPTEE_SMC_RETURN_ENOTAVAIL);
        return true;

    case OPTEE_SMC_EXCHANGE_CAPABILITIES:
        handle_exchange_capabilities(regs);
        return true;

    case OPTEE_SMC_CALL_WITH_ARG:
        handle_std_call(ctx, regs);
        return true;

    case OPTEE_SMC_CALL_RETURN_FROM_RPC:
        handle_rpc(ctx, regs);
        return true;

    default:
        return false;
    }
}

static const struct tee_mediator_ops optee_ops =
{
    .probe = optee_probe,
    .domain_init = optee_domain_init,
    .relinquish_resources = optee_relinquish_resources,
    .handle_call = optee_handle_call,
};

REGISTER_TEE_MEDIATOR(optee, "OP-TEE", XEN_DOMCTL_CONFIG_TEE_OPTEE, &optee_ops);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
