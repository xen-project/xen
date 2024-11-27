/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024  Linaro Limited
 */

#include <xen/const.h>
#include <xen/sizes.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/list.h>
#include <xen/spinlock.h>

#include <asm/smccc.h>
#include <asm/regs.h>

#include "ffa_private.h"

/* Memory access permissions descriptor */
struct ffa_mem_access_perm {
    uint16_t endpoint_id;
    uint8_t perm;
    uint8_t flags;
};

/* Endpoint memory access descriptor */
struct ffa_mem_access {
    struct ffa_mem_access_perm access_perm;
    uint32_t region_offs;
    uint64_t reserved;
};

/* Lend, donate or share memory transaction descriptor */
struct ffa_mem_transaction_1_0 {
    uint16_t sender_id;
    uint8_t mem_reg_attr;
    uint8_t reserved0;
    uint32_t flags;
    uint64_t handle;
    uint64_t tag;
    uint32_t reserved1;
    uint32_t mem_access_count;
    struct ffa_mem_access mem_access_array[];
};

struct ffa_mem_transaction_1_1 {
    uint16_t sender_id;
    uint16_t mem_reg_attr;
    uint32_t flags;
    uint64_t handle;
    uint64_t tag;
    uint32_t mem_access_size;
    uint32_t mem_access_count;
    uint32_t mem_access_offs;
    uint8_t reserved[12];
};

/* Calculate offset of struct ffa_mem_access from start of buffer */
#define MEM_ACCESS_OFFSET(access_idx) \
    ( sizeof(struct ffa_mem_transaction_1_1) + \
      ( access_idx ) * sizeof(struct ffa_mem_access) )

/* Calculate offset of struct ffa_mem_region from start of buffer */
#define REGION_OFFSET(access_count, region_idx) \
    ( MEM_ACCESS_OFFSET(access_count) + \
      ( region_idx ) * sizeof(struct ffa_mem_region) )

/* Calculate offset of struct ffa_address_range from start of buffer */
#define ADDR_RANGE_OFFSET(access_count, region_count, range_idx) \
    ( REGION_OFFSET(access_count, region_count) + \
      ( range_idx ) * sizeof(struct ffa_address_range) )

/*
 * The parts needed from struct ffa_mem_transaction_1_0 or struct
 * ffa_mem_transaction_1_1, used to provide an abstraction of difference in
 * data structures between version 1.0 and 1.1. This is just an internal
 * interface and can be changed without changing any ABI.
 */
struct ffa_mem_transaction_int {
    uint16_t sender_id;
    uint8_t mem_reg_attr;
    uint8_t flags;
    uint8_t mem_access_size;
    uint8_t mem_access_count;
    uint16_t mem_access_offs;
    uint64_t handle;
    uint64_t tag;
};

struct ffa_shm_mem {
    struct list_head list;
    uint16_t sender_id;
    uint16_t ep_id;     /* endpoint, the one lending */
    uint64_t handle;    /* FFA_HANDLE_INVALID if not set yet */
    unsigned int page_count;
    struct page_info *pages[];
};

static int32_t ffa_mem_share(uint32_t tot_len, uint32_t frag_len,
                             register_t addr, uint32_t pg_count,
                             uint64_t *handle)
{
    struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_MEM_SHARE_64,
        .a1 = tot_len,
        .a2 = frag_len,
        .a3 = addr,
        .a4 = pg_count,
    };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);

    switch ( resp.a0 )
    {
    case FFA_ERROR:
        if ( resp.a2 )
            return resp.a2;
        else
            return FFA_RET_NOT_SUPPORTED;
    case FFA_SUCCESS_32:
        *handle = regpair_to_uint64(resp.a3, resp.a2);
        return FFA_RET_OK;
    case FFA_MEM_FRAG_RX:
        *handle = regpair_to_uint64(resp.a2, resp.a1);
        if ( resp.a3 > INT32_MAX ) /* Impossible value */
            return FFA_RET_ABORTED;
        return resp.a3 & INT32_MAX;
    default:
        return FFA_RET_NOT_SUPPORTED;
    }
}

static int32_t ffa_mem_reclaim(uint32_t handle_lo, uint32_t handle_hi,
                               uint32_t flags)
{
    if ( !ffa_fw_supports_fid(FFA_MEM_RECLAIM) )
        return FFA_RET_NOT_SUPPORTED;

    return ffa_simple_call(FFA_MEM_RECLAIM, handle_lo, handle_hi, flags, 0);
}

/*
 * Gets all page and assigns them to the supplied shared memory object. If
 * this function fails then the caller is still expected to call
 * put_shm_pages() as a cleanup.
 */
static int get_shm_pages(struct domain *d, struct ffa_shm_mem *shm,
                         const struct ffa_address_range *range,
                         uint32_t range_count)
{
    unsigned int pg_idx = 0;
    gfn_t gfn;
    unsigned int n;
    unsigned int m;
    p2m_type_t t;
    uint64_t addr;
    uint64_t page_count;

    for ( n = 0; n < range_count; n++ )
    {
        page_count = ACCESS_ONCE(range[n].page_count);
        addr = ACCESS_ONCE(range[n].address);
        for ( m = 0; m < page_count; m++ )
        {
            if ( pg_idx >= shm->page_count )
                return FFA_RET_INVALID_PARAMETERS;

            gfn = gaddr_to_gfn(addr + m * FFA_PAGE_SIZE);
            shm->pages[pg_idx] = get_page_from_gfn(d, gfn_x(gfn), &t,
						   P2M_ALLOC);
            if ( !shm->pages[pg_idx] )
                return FFA_RET_DENIED;
            /* Only normal RW RAM for now */
            if ( t != p2m_ram_rw )
                return FFA_RET_DENIED;
            pg_idx++;
        }
    }

    /* The ranges must add up */
    if ( pg_idx < shm->page_count )
            return FFA_RET_INVALID_PARAMETERS;

    return FFA_RET_OK;
}

static void put_shm_pages(struct ffa_shm_mem *shm)
{
    unsigned int n;

    for ( n = 0; n < shm->page_count && shm->pages[n]; n++ )
    {
        put_page(shm->pages[n]);
        shm->pages[n] = NULL;
    }
}

static bool inc_ctx_shm_count(struct domain *d, struct ffa_ctx *ctx)
{
    bool ret = true;

    spin_lock(&ctx->lock);

    if ( ctx->shm_count >= FFA_MAX_SHM_COUNT )
    {
        ret = false;
    }
    else
    {
        /*
         * If this is the first shm added, increase the domain reference
         * counter as we need to keep domain around a bit longer to reclaim
         * the shared memory in the teardown path.
         */
        if ( !ctx->shm_count )
            get_knownalive_domain(d);

        ctx->shm_count++;
    }

    spin_unlock(&ctx->lock);

    return ret;
}

static void dec_ctx_shm_count(struct domain *d, struct ffa_ctx *ctx)
{
    bool drop_ref;

    spin_lock(&ctx->lock);

    ASSERT(ctx->shm_count > 0);
    ctx->shm_count--;

    /*
     * If this was the last shm removed, let go of the domain reference we
     * took in inc_ctx_shm_count() above.
     */
    drop_ref = !ctx->shm_count;

    spin_unlock(&ctx->lock);

    if ( drop_ref )
        put_domain(d);
}

static struct ffa_shm_mem *alloc_ffa_shm_mem(struct domain *d,
                                             unsigned int page_count)
{
    struct ffa_ctx *ctx = d->arch.tee;
    struct ffa_shm_mem *shm;

    if ( page_count >= FFA_MAX_SHM_PAGE_COUNT )
        return NULL;
    if ( !inc_ctx_shm_count(d, ctx) )
        return NULL;

    shm = xzalloc_flex_struct(struct ffa_shm_mem, pages, page_count);
    if ( shm )
        shm->page_count = page_count;
    else
        dec_ctx_shm_count(d, ctx);

    return shm;
}

static void free_ffa_shm_mem(struct domain *d, struct ffa_shm_mem *shm)
{
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !shm )
        return;

    dec_ctx_shm_count(d, ctx);
    put_shm_pages(shm);
    xfree(shm);
}

static void init_range(struct ffa_address_range *addr_range,
                       paddr_t pa)
{
    memset(addr_range, 0, sizeof(*addr_range));
    addr_range->address = pa;
    addr_range->page_count = 1;
}

/*
 * This function uses the ffa_tx buffer to transmit the memory transaction
 * descriptor. The function depends ffa_tx_buffer_lock to be used to guard
 * the buffer from concurrent use.
 */
static int share_shm(struct ffa_shm_mem *shm)
{
    const uint32_t max_frag_len = FFA_RXTX_PAGE_COUNT * FFA_PAGE_SIZE;
    struct ffa_mem_access *mem_access_array;
    struct ffa_mem_transaction_1_1 *descr;
    struct ffa_address_range *addr_range;
    struct ffa_mem_region *region_descr;
    const unsigned int region_count = 1;
    void *buf = ffa_tx;
    uint32_t frag_len;
    uint32_t tot_len;
    paddr_t last_pa;
    unsigned int n;
    paddr_t pa;

    ASSERT(spin_is_locked(&ffa_tx_buffer_lock));
    ASSERT(shm->page_count);

    descr = buf;
    memset(descr, 0, sizeof(*descr));
    descr->sender_id = shm->sender_id;
    descr->handle = shm->handle;
    descr->mem_reg_attr = FFA_NORMAL_MEM_REG_ATTR;
    descr->mem_access_count = 1;
    descr->mem_access_size = sizeof(*mem_access_array);
    descr->mem_access_offs = MEM_ACCESS_OFFSET(0);

    mem_access_array = buf + descr->mem_access_offs;
    memset(mem_access_array, 0, sizeof(*mem_access_array));
    mem_access_array[0].access_perm.endpoint_id = shm->ep_id;
    mem_access_array[0].access_perm.perm = FFA_MEM_ACC_RW;
    mem_access_array[0].region_offs = REGION_OFFSET(descr->mem_access_count, 0);

    region_descr = buf + mem_access_array[0].region_offs;
    memset(region_descr, 0, sizeof(*region_descr));
    region_descr->total_page_count = shm->page_count;

    region_descr->address_range_count = 1;
    last_pa = page_to_maddr(shm->pages[0]);
    for ( n = 1; n < shm->page_count; last_pa = pa, n++ )
    {
        pa = page_to_maddr(shm->pages[n]);
        if ( last_pa + FFA_PAGE_SIZE == pa )
            continue;
        region_descr->address_range_count++;
    }

    tot_len = ADDR_RANGE_OFFSET(descr->mem_access_count, region_count,
                                region_descr->address_range_count);
    if ( tot_len > max_frag_len )
        return FFA_RET_NOT_SUPPORTED;

    addr_range = region_descr->address_range_array;
    frag_len = ADDR_RANGE_OFFSET(descr->mem_access_count, region_count, 1);
    last_pa = page_to_maddr(shm->pages[0]);
    init_range(addr_range, last_pa);
    for ( n = 1; n < shm->page_count; last_pa = pa, n++ )
    {
        pa = page_to_maddr(shm->pages[n]);
        if ( last_pa + FFA_PAGE_SIZE == pa )
        {
            addr_range->page_count++;
            continue;
        }

        frag_len += sizeof(*addr_range);
        addr_range++;
        init_range(addr_range, pa);
    }

    return ffa_mem_share(tot_len, frag_len, 0, 0, &shm->handle);
}

static int read_mem_transaction(uint32_t ffa_vers, const void *buf, size_t blen,
                                struct ffa_mem_transaction_int *trans)
{
    uint16_t mem_reg_attr;
    uint32_t flags;
    uint32_t count;
    uint32_t offs;
    uint32_t size;

    if ( ffa_vers >= FFA_VERSION_1_1 )
    {
        const struct ffa_mem_transaction_1_1 *descr;

        if ( blen < sizeof(*descr) )
            return FFA_RET_INVALID_PARAMETERS;

        descr = buf;
        trans->sender_id = descr->sender_id;
        mem_reg_attr = descr->mem_reg_attr;
        flags = descr->flags;
        trans->handle = descr->handle;
        trans->tag = descr->tag;

        count = descr->mem_access_count;
        size = descr->mem_access_size;
        offs = descr->mem_access_offs;
    }
    else
    {
        const struct ffa_mem_transaction_1_0 *descr;

        if ( blen < sizeof(*descr) )
            return FFA_RET_INVALID_PARAMETERS;

        descr = buf;
        trans->sender_id = descr->sender_id;
        mem_reg_attr = descr->mem_reg_attr;
        flags = descr->flags;
        trans->handle = descr->handle;
        trans->tag = descr->tag;

        count = descr->mem_access_count;
        size = sizeof(struct ffa_mem_access);
        offs = offsetof(struct ffa_mem_transaction_1_0, mem_access_array);
    }
    /*
     * Make sure that "descr" which is shared with the guest isn't accessed
     * again after this point.
     */
    barrier();

    /*
     * We're doing a rough check to see that no information is lost when
     * tranfering the values into a struct ffa_mem_transaction_int below.
     * The fields in struct ffa_mem_transaction_int are wide enough to hold
     * any valid value so being out of range means that something is wrong.
     */
    if ( mem_reg_attr > UINT8_MAX || flags > UINT8_MAX || size > UINT8_MAX ||
        count > UINT8_MAX || offs > UINT16_MAX )
        return FFA_RET_INVALID_PARAMETERS;

    /* Check that the endpoint memory access descriptor array fits */
    if ( size * count + offs > blen )
        return FFA_RET_INVALID_PARAMETERS;

    trans->mem_reg_attr = mem_reg_attr;
    trans->flags = flags;
    trans->mem_access_size = size;
    trans->mem_access_count = count;
    trans->mem_access_offs = offs;

    return 0;
}

void ffa_handle_mem_share(struct cpu_user_regs *regs)
{
    uint32_t tot_len = get_user_reg(regs, 1);
    uint32_t frag_len = get_user_reg(regs, 2);
    uint64_t addr = get_user_reg(regs, 3);
    uint32_t page_count = get_user_reg(regs, 4);
    const struct ffa_mem_region *region_descr;
    const struct ffa_mem_access *mem_access;
    struct ffa_mem_transaction_int trans;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    struct ffa_shm_mem *shm = NULL;
    register_t handle_hi = 0;
    register_t handle_lo = 0;
    int ret = FFA_RET_DENIED;
    uint32_t range_count;
    uint32_t region_offs;
    uint16_t dst_id;

    if ( !ffa_fw_supports_fid(FFA_MEM_SHARE_64) )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_set_ret;
    }

    /*
     * We're only accepting memory transaction descriptors via the rx/tx
     * buffer.
     */
    if ( addr )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_set_ret;
    }

    /* Check that fragment length doesn't exceed total length */
    if ( frag_len > tot_len )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out_set_ret;
    }

    /* We currently only support a single fragment */
    if ( frag_len != tot_len )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_set_ret;
    }

    if ( !spin_trylock(&ctx->tx_lock) )
    {
        ret = FFA_RET_BUSY;
        goto out_set_ret;
    }

    if ( frag_len > ctx->page_count * FFA_PAGE_SIZE )
        goto out_unlock;

    ret = read_mem_transaction(ctx->guest_vers, ctx->tx, frag_len, &trans);
    if ( ret )
        goto out_unlock;

    if ( trans.mem_reg_attr != FFA_NORMAL_MEM_REG_ATTR )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_unlock;
    }

    /* Only supports sharing it with one SP for now */
    if ( trans.mem_access_count != 1 )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_unlock;
    }

    if ( trans.sender_id != ffa_get_vm_id(d) )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out_unlock;
    }

    /* Check that it fits in the supplied data */
    if ( trans.mem_access_offs + trans.mem_access_size > frag_len )
        goto out_unlock;

    mem_access = ctx->tx + trans.mem_access_offs;

    dst_id = ACCESS_ONCE(mem_access->access_perm.endpoint_id);
    if ( !FFA_ID_IS_SECURE(dst_id) )
    {
        /* we do not support sharing with VMs */
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_unlock;
    }

    if ( ACCESS_ONCE(mem_access->access_perm.perm) != FFA_MEM_ACC_RW )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_unlock;
    }

    region_offs = ACCESS_ONCE(mem_access->region_offs);
    if ( sizeof(*region_descr) + region_offs > frag_len )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_unlock;
    }

    region_descr = ctx->tx + region_offs;
    range_count = ACCESS_ONCE(region_descr->address_range_count);
    page_count = ACCESS_ONCE(region_descr->total_page_count);

    if ( !page_count )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out_unlock;
    }

    shm = alloc_ffa_shm_mem(d, page_count);
    if ( !shm )
    {
        ret = FFA_RET_NO_MEMORY;
        goto out_unlock;
    }
    shm->sender_id = trans.sender_id;
    shm->ep_id = dst_id;

    /*
     * Check that the Composite memory region descriptor fits.
     */
    if ( sizeof(*region_descr) + region_offs +
         range_count * sizeof(struct ffa_address_range) > frag_len )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out;
    }

    ret = get_shm_pages(d, shm, region_descr->address_range_array, range_count);
    if ( ret )
        goto out;

    /* Note that share_shm() uses our tx buffer */
    spin_lock(&ffa_tx_buffer_lock);
    ret = share_shm(shm);
    spin_unlock(&ffa_tx_buffer_lock);
    if ( ret )
        goto out;

    spin_lock(&ctx->lock);
    list_add_tail(&shm->list, &ctx->shm_list);
    spin_unlock(&ctx->lock);

    uint64_to_regpair(&handle_hi, &handle_lo, shm->handle);

out:
    if ( ret )
        free_ffa_shm_mem(d, shm);
out_unlock:
    spin_unlock(&ctx->tx_lock);

out_set_ret:
    if ( ret == 0)
            ffa_set_regs_success(regs, handle_lo, handle_hi);
    else
            ffa_set_regs_error(regs, ret);
}

/* Must only be called with ctx->lock held */
static struct ffa_shm_mem *find_shm_mem(struct ffa_ctx *ctx, uint64_t handle)
{
    struct ffa_shm_mem *shm;

    list_for_each_entry(shm, &ctx->shm_list, list)
        if ( shm->handle == handle )
            return shm;

    return NULL;
}

int ffa_handle_mem_reclaim(uint64_t handle, uint32_t flags)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    struct ffa_shm_mem *shm;
    register_t handle_hi;
    register_t handle_lo;
    int ret;

    if ( !ffa_fw_supports_fid(FFA_MEM_RECLAIM) )
        return FFA_RET_NOT_SUPPORTED;

    spin_lock(&ctx->lock);
    shm = find_shm_mem(ctx, handle);
    if ( shm )
        list_del(&shm->list);
    spin_unlock(&ctx->lock);
    if ( !shm )
        return FFA_RET_INVALID_PARAMETERS;

    uint64_to_regpair(&handle_hi, &handle_lo, handle);
    ret = ffa_mem_reclaim(handle_lo, handle_hi, flags);

    if ( ret )
    {
        spin_lock(&ctx->lock);
        list_add_tail(&shm->list, &ctx->shm_list);
        spin_unlock(&ctx->lock);
    }
    else
    {
        free_ffa_shm_mem(d, shm);
    }

    return ret;
}

bool ffa_shm_domain_destroy(struct domain *d)
{
    struct ffa_ctx *ctx = d->arch.tee;
    struct ffa_shm_mem *shm, *tmp;
    int32_t res;

    list_for_each_entry_safe(shm, tmp, &ctx->shm_list, list)
    {
        register_t handle_hi;
        register_t handle_lo;

        uint64_to_regpair(&handle_hi, &handle_lo, shm->handle);
        res = ffa_mem_reclaim(handle_lo, handle_hi, 0);
        switch ( res ) {
        case FFA_RET_OK:
            printk(XENLOG_G_DEBUG "%pd: ffa: Reclaimed handle %#lx\n",
                   d, shm->handle);
            list_del(&shm->list);
            free_ffa_shm_mem(d, shm);
            break;
        case FFA_RET_DENIED:
            /*
             * A temporary error that may get resolved a bit later, it's
             * worth retrying.
             */
            printk(XENLOG_G_INFO "%pd: ffa: Failed to reclaim handle %#lx : %d\n",
                   d, shm->handle, res);
            break; /* We will retry later */
        default:
            /*
             * The rest of the error codes are not expected and are assumed
             * to be of a permanent nature. It not in our control to handle
             * the error properly so the object in this case is to try to
             * minimize the damage.
             *
             * FFA_RET_NO_MEMORY might be a temporary error as it it could
             * succeed if retried later, but treat it as permanent for now.
             */
            printk(XENLOG_G_INFO "%pd: ffa: Permanent failure to reclaim handle %#lx : %d\n",
                   d, shm->handle, res);

            /*
             * Remove the shm from the list and free it, but don't drop
             * references. This results in having the shared physical pages
             * permanently allocate and also keeps the domain as a zombie
             * domain.
             */
            list_del(&shm->list);
            xfree(shm);
            break;
        }
    }

    return !ctx->shm_count;
}
