/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024  Linaro Limited
 */

#include <xen/const.h>
#include <xen/domain_page.h>
#include <xen/mm.h>
#include <xen/sizes.h>
#include <xen/types.h>

#include <asm/smccc.h>
#include <asm/regs.h>

#include "ffa_private.h"

/* Endpoint RX/TX descriptor defined in FF-A-1.0-REL */
struct ffa_endpoint_rxtx_descriptor_1_0 {
    uint16_t sender_id;
    uint16_t reserved;
    uint32_t rx_range_count;
    uint32_t tx_range_count;
};

/* Endpoint RX/TX descriptor defined in FF-A-1.1-REL0 */
struct ffa_endpoint_rxtx_descriptor_1_1 {
    uint16_t sender_id;
    uint16_t reserved;
    uint32_t rx_region_offs;
    uint32_t tx_region_offs;
};

/*
 * Our rx/tx buffers shared with the SPMC. FFA_RXTX_PAGE_COUNT is the
 * number of pages used in each of these buffers.
 * Each buffer has its own lock to protect from concurrent usage.
 *
 * Note that the SPMC is also tracking the ownership of our RX buffer so
 * for calls which uses our RX buffer to deliver a result we must do an
 * FFA_RX_RELEASE to let the SPMC know that we're done with the buffer.
 */
static void *ffa_spmc_rx __read_mostly;
static void *ffa_spmc_tx __read_mostly;
static DEFINE_SPINLOCK(ffa_spmc_rx_lock);
static DEFINE_SPINLOCK(ffa_spmc_tx_lock);

static int32_t ffa_rxtx_map(paddr_t tx_addr, paddr_t rx_addr,
                            uint32_t page_count)
{
    return ffa_simple_call(FFA_RXTX_MAP_64, tx_addr, rx_addr, page_count, 0);
}

static int32_t ffa_rxtx_unmap(uint16_t id)
{
    return ffa_simple_call(FFA_RXTX_UNMAP, ((uint64_t)id) << 16, 0, 0, 0);
}

int32_t ffa_handle_rxtx_map(uint32_t fid, register_t tx_addr,
			     register_t rx_addr, uint32_t page_count)
{
    int32_t ret = FFA_RET_INVALID_PARAMETERS;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    struct page_info *tx_pg;
    struct page_info *rx_pg;
    p2m_type_t t;
    void *rx;
    void *tx;

    /* The code is considering that we only get one page for now */
    BUILD_BUG_ON(FFA_MAX_RXTX_PAGE_COUNT != 1);

    if ( !smccc_is_conv_64(fid) )
    {
        /*
         * Calls using the 32-bit calling convention must ignore the upper
         * 32 bits in the argument registers.
         */
        tx_addr &= UINT32_MAX;
        rx_addr &= UINT32_MAX;
    }

    if ( page_count > FFA_MAX_RXTX_PAGE_COUNT || !page_count )
    {
        printk(XENLOG_ERR "ffa: RXTX_MAP: error: %u pages requested (limit %u)\n",
               page_count, FFA_MAX_RXTX_PAGE_COUNT);
        return FFA_RET_INVALID_PARAMETERS;
    }

    if ( !IS_ALIGNED(tx_addr, FFA_PAGE_SIZE) ||
         !IS_ALIGNED(rx_addr, FFA_PAGE_SIZE) )
        return FFA_RET_INVALID_PARAMETERS;

    spin_lock(&ctx->rx_lock);
    spin_lock(&ctx->tx_lock);

    /* Already mapped */
    if ( ctx->rx )
    {
        ret = FFA_RET_DENIED;
        goto err_unlock_rxtx;
    }

    tx_pg = get_page_from_gfn(d, gfn_x(gaddr_to_gfn(tx_addr)), &t, P2M_ALLOC);
    if ( !tx_pg )
        goto err_unlock_rxtx;

    /* Only normal RW RAM for now */
    if ( t != p2m_ram_rw )
        goto err_put_tx_pg;

    rx_pg = get_page_from_gfn(d, gfn_x(gaddr_to_gfn(rx_addr)), &t, P2M_ALLOC);
    if ( !rx_pg )
        goto err_put_tx_pg;

    /* Only normal RW RAM for now */
    if ( t != p2m_ram_rw )
        goto err_put_rx_pg;

    tx = __map_domain_page_global(tx_pg);
    if ( !tx )
        goto err_put_rx_pg;

    rx = __map_domain_page_global(rx_pg);
    if ( !rx )
        goto err_unmap_tx;

    /*
     * Transmit the RX/TX buffer information to the SPM if acquire is supported
     * as the spec says that if not there is not need to acquire/release/map
     * rxtx buffers from the SPMC
     */
    if ( ffa_fw_supports_fid(FFA_RX_ACQUIRE) )
    {
        struct ffa_endpoint_rxtx_descriptor_1_1 *rxtx_desc;
        struct ffa_mem_region *mem_reg;

        /* All must fit in our TX buffer */
        BUILD_BUG_ON(sizeof(*rxtx_desc) + sizeof(*mem_reg) * 2 +
                     sizeof(struct ffa_address_range) * 2 >
                     FFA_MAX_RXTX_PAGE_COUNT * FFA_PAGE_SIZE);

        rxtx_desc = ffa_rxtx_spmc_tx_acquire();
        if ( !rxtx_desc )
            goto err_unmap_rx;

        /*
         * We have only one page for each so we pack everything:
         * - rx region descriptor
         * - rx region range
         * - tx region descriptor
         * - tx region range
         */
        rxtx_desc->sender_id = ffa_get_vm_id(d);
        rxtx_desc->reserved = 0;
        rxtx_desc->rx_region_offs = sizeof(*rxtx_desc);
        rxtx_desc->tx_region_offs = sizeof(*rxtx_desc) +
                                    offsetof(struct ffa_mem_region,
                                             address_range_array[1]);

        /* rx buffer */
        mem_reg = (void *)rxtx_desc + rxtx_desc->rx_region_offs;
        mem_reg->total_page_count = 1;
        mem_reg->address_range_count = 1;
        mem_reg->reserved = 0;

        mem_reg->address_range_array[0].address = page_to_maddr(rx_pg);
        mem_reg->address_range_array[0].page_count = 1;
        mem_reg->address_range_array[0].reserved = 0;

        /* tx buffer */
        mem_reg = (void *)rxtx_desc + rxtx_desc->tx_region_offs;
        mem_reg->total_page_count = 1;
        mem_reg->address_range_count = 1;
        mem_reg->reserved = 0;

        mem_reg->address_range_array[0].address = page_to_maddr(tx_pg);
        mem_reg->address_range_array[0].page_count = 1;
        mem_reg->address_range_array[0].reserved = 0;

        ret = ffa_rxtx_map(0, 0, 0);

        ffa_rxtx_spmc_tx_release();

        if ( ret != FFA_RET_OK )
            goto err_unmap_rx;
    }

    ctx->rx = rx;
    ctx->tx = tx;
    ctx->rx_pg = rx_pg;
    ctx->tx_pg = tx_pg;
    ctx->page_count = page_count;
    ctx->rx_is_free = true;

    spin_unlock(&ctx->tx_lock);
    spin_unlock(&ctx->rx_lock);

    return FFA_RET_OK;

err_unmap_rx:
    unmap_domain_page_global(rx);
err_unmap_tx:
    unmap_domain_page_global(tx);
err_put_rx_pg:
    put_page(rx_pg);
err_put_tx_pg:
    put_page(tx_pg);
err_unlock_rxtx:
    spin_unlock(&ctx->tx_lock);
    spin_unlock(&ctx->rx_lock);

    return ret;
}

static int32_t rxtx_unmap(struct domain *d)
{
    struct ffa_ctx *ctx = d->arch.tee;
    int32_t ret = FFA_RET_OK;

    spin_lock(&ctx->rx_lock);
    spin_lock(&ctx->tx_lock);

    if ( !ctx->page_count )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto err_unlock_rxtx;
    }

    if ( ffa_fw_supports_fid(FFA_RX_ACQUIRE) )
    {
        ret = ffa_rxtx_unmap(ffa_get_vm_id(d));
        if ( ret != FFA_RET_OK )
            goto err_unlock_rxtx;
    }

    unmap_domain_page_global(ctx->rx);
    unmap_domain_page_global(ctx->tx);
    put_page(ctx->rx_pg);
    put_page(ctx->tx_pg);
    ctx->rx = NULL;
    ctx->tx = NULL;
    ctx->rx_pg = NULL;
    ctx->tx_pg = NULL;
    ctx->page_count = 0;
    ctx->rx_is_free = false;

err_unlock_rxtx:
    spin_unlock(&ctx->tx_lock);
    spin_unlock(&ctx->rx_lock);

    return ret;
}

int32_t ffa_handle_rxtx_unmap(void)
{
    return rxtx_unmap(current->domain);
}

int32_t ffa_rx_acquire(struct ffa_ctx *ctx, void **buf, size_t *buf_size)
{
    int32_t ret = FFA_RET_OK;

    spin_lock(&ctx->rx_lock);

    if ( !ctx->page_count )
    {
        ret = FFA_RET_DENIED;
        goto out;
    }

    if ( !ctx->rx_is_free )
    {
        ret = FFA_RET_BUSY;
        goto out;
    }

    if ( ffa_fw_supports_fid(FFA_RX_ACQUIRE) )
    {
        ret = ffa_simple_call(FFA_RX_ACQUIRE, ctx->ffa_id, 0, 0, 0);
        if ( ret != FFA_RET_OK )
            goto out;
    }
    ctx->rx_is_free = false;
    *buf = ctx->rx;
    *buf_size = ctx->page_count * FFA_PAGE_SIZE;
out:
    spin_unlock(&ctx->rx_lock);

    return ret;
}

int32_t ffa_rx_release(struct ffa_ctx *ctx)
{
    int32_t ret = FFA_RET_DENIED;

    spin_lock(&ctx->rx_lock);

    if ( !ctx->page_count || ctx->rx_is_free )
        goto out;

    if ( ffa_fw_supports_fid(FFA_RX_ACQUIRE) )
    {
        ret = ffa_simple_call(FFA_RX_RELEASE, ctx->ffa_id, 0, 0, 0);
        if ( ret != FFA_RET_OK )
            goto out;
    }
    ret = FFA_RET_OK;
    ctx->rx_is_free = true;
out:
    spin_unlock(&ctx->rx_lock);

    return ret;
}

int32_t ffa_tx_acquire(struct ffa_ctx *ctx, const void **buf, size_t *buf_size)
{
    int32_t ret = FFA_RET_DENIED;

    if ( !spin_trylock(&ctx->tx_lock) )
        return FFA_RET_BUSY;

    if ( !ctx->page_count )
        goto err_unlock;

    if ( !ctx->tx )
        goto err_unlock;

    *buf = ctx->tx;
    *buf_size = ctx->page_count * FFA_PAGE_SIZE;
    return FFA_RET_OK;

err_unlock:
    spin_unlock(&ctx->tx_lock);

    return ret;
}

int32_t ffa_tx_release(struct ffa_ctx *ctx)
{
    ASSERT(spin_is_locked(&ctx->tx_lock));

    spin_unlock(&ctx->tx_lock);
    return FFA_RET_OK;
}

int32_t ffa_rxtx_domain_init(struct domain *d)
{
    struct ffa_ctx *ctx = d->arch.tee;

    spin_lock_init(&ctx->rx_lock);
    spin_lock_init(&ctx->tx_lock);
    ctx->rx = NULL;
    ctx->tx = NULL;
    ctx->rx_pg = NULL;
    ctx->tx_pg = NULL;
    ctx->page_count = 0;
    ctx->rx_is_free = false;

    return 0;
}

void ffa_rxtx_domain_destroy(struct domain *d)
{
    rxtx_unmap(d);
}

void *ffa_rxtx_spmc_rx_acquire(void)
{
    spin_lock(&ffa_spmc_rx_lock);

    if ( ffa_spmc_rx )
        return ffa_spmc_rx;

    return NULL;
}

void ffa_rxtx_spmc_rx_release(void)
{
    int32_t ret;

    ASSERT(spin_is_locked(&ffa_spmc_rx_lock));

    /* Inform the SPMC that we are done with our RX buffer */
    ret = ffa_simple_call(FFA_RX_RELEASE, 0, 0, 0, 0);
    if ( ret != FFA_RET_OK )
        printk(XENLOG_DEBUG "Error releasing SPMC RX buffer: %d\n", ret);

    spin_unlock(&ffa_spmc_rx_lock);
}

void *ffa_rxtx_spmc_tx_acquire(void)
{
    spin_lock(&ffa_spmc_tx_lock);

    if ( ffa_spmc_tx )
        return ffa_spmc_tx;

    return NULL;
}

void ffa_rxtx_spmc_tx_release(void)
{
    ASSERT(spin_is_locked(&ffa_spmc_tx_lock));

    spin_unlock(&ffa_spmc_tx_lock);
}

void ffa_rxtx_spmc_destroy(void)
{
    bool need_unmap;

    spin_lock(&ffa_spmc_rx_lock);
    spin_lock(&ffa_spmc_tx_lock);
    need_unmap = ffa_spmc_tx && ffa_spmc_rx;

    if ( ffa_spmc_tx )
    {
        free_xenheap_pages(ffa_spmc_tx, 0);
        ffa_spmc_tx = NULL;
    }
    if ( ffa_spmc_rx )
    {
        free_xenheap_pages(ffa_spmc_rx, 0);
        ffa_spmc_rx = NULL;
    }

    if ( need_unmap )
        ffa_rxtx_unmap(0);

    spin_unlock(&ffa_spmc_tx_lock);
    spin_unlock(&ffa_spmc_rx_lock);
}

bool ffa_rxtx_spmc_init(void)
{
    int32_t e;
    bool ret = false;

    /* Firmware not there or not supporting */
    if ( !ffa_fw_supports_fid(FFA_RXTX_MAP_64) )
        return false;

    spin_lock(&ffa_spmc_rx_lock);
    spin_lock(&ffa_spmc_tx_lock);

    ffa_spmc_rx = alloc_xenheap_pages(
                            get_order_from_pages(FFA_RXTX_PAGE_COUNT), 0);
    if ( !ffa_spmc_rx )
        goto exit;

    ffa_spmc_tx = alloc_xenheap_pages(
                            get_order_from_pages(FFA_RXTX_PAGE_COUNT), 0);
    if ( !ffa_spmc_tx )
        goto exit;

    e = ffa_rxtx_map(__pa(ffa_spmc_tx), __pa(ffa_spmc_rx),
                     FFA_RXTX_PAGE_COUNT);
    if ( e )
        goto exit;

    ret = true;

exit:
    spin_unlock(&ffa_spmc_tx_lock);
    spin_unlock(&ffa_spmc_rx_lock);

    if ( !ret )
        ffa_rxtx_spmc_destroy();

    return ret;
}
