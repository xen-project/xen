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

static int32_t ffa_rxtx_map(paddr_t tx_addr, paddr_t rx_addr,
                            uint32_t page_count)
{
    return ffa_simple_call(FFA_RXTX_MAP_64, tx_addr, rx_addr, page_count, 0);
}

static int32_t ffa_rxtx_unmap(uint16_t id)
{
    return ffa_simple_call(FFA_RXTX_UNMAP, ((uint64_t)id) << 16, 0, 0, 0);
}

uint32_t ffa_handle_rxtx_map(uint32_t fid, register_t tx_addr,
			     register_t rx_addr, uint32_t page_count)
{
    uint32_t ret = FFA_RET_INVALID_PARAMETERS;
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

    if ( page_count > FFA_MAX_RXTX_PAGE_COUNT )
    {
        printk(XENLOG_ERR "ffa: RXTX_MAP: error: %u pages requested (limit %u)\n",
               page_count, FFA_MAX_RXTX_PAGE_COUNT);
        return FFA_RET_INVALID_PARAMETERS;
    }

    /* Already mapped */
    if ( ctx->rx )
        return FFA_RET_DENIED;

    tx_pg = get_page_from_gfn(d, gfn_x(gaddr_to_gfn(tx_addr)), &t, P2M_ALLOC);
    if ( !tx_pg )
        return FFA_RET_INVALID_PARAMETERS;

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

        spin_lock(&ffa_tx_buffer_lock);
        rxtx_desc = ffa_tx;

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
        mem_reg = ffa_tx + sizeof(*rxtx_desc);
        mem_reg->total_page_count = 1;
        mem_reg->address_range_count = 1;
        mem_reg->reserved = 0;

        mem_reg->address_range_array[0].address = page_to_maddr(rx_pg);
        mem_reg->address_range_array[0].page_count = 1;
        mem_reg->address_range_array[0].reserved = 0;

        /* tx buffer */
        mem_reg = ffa_tx + rxtx_desc->tx_region_offs;
        mem_reg->total_page_count = 1;
        mem_reg->address_range_count = 1;
        mem_reg->reserved = 0;

        mem_reg->address_range_array[0].address = page_to_maddr(tx_pg);
        mem_reg->address_range_array[0].page_count = 1;
        mem_reg->address_range_array[0].reserved = 0;

        ret = ffa_rxtx_map(0, 0, 0);

        spin_unlock(&ffa_tx_buffer_lock);

        if ( ret != FFA_RET_OK )
            goto err_unmap_rx;
    }

    ctx->rx = rx;
    ctx->tx = tx;
    ctx->rx_pg = rx_pg;
    ctx->tx_pg = tx_pg;
    ctx->page_count = page_count;
    ctx->rx_is_free = true;
    return FFA_RET_OK;

err_unmap_rx:
    unmap_domain_page_global(rx);
err_unmap_tx:
    unmap_domain_page_global(tx);
err_put_rx_pg:
    put_page(rx_pg);
err_put_tx_pg:
    put_page(tx_pg);

    return ret;
}

static uint32_t  rxtx_unmap(struct domain *d)
{
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !ctx->page_count )
        return FFA_RET_INVALID_PARAMETERS;

    if ( ffa_fw_supports_fid(FFA_RX_ACQUIRE) )
    {
        uint32_t ret;

        ret = ffa_rxtx_unmap(ffa_get_vm_id(d));
        if ( ret != FFA_RET_OK )
            return ret;
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

    return FFA_RET_OK;
}

uint32_t ffa_handle_rxtx_unmap(void)
{
    return rxtx_unmap(current->domain);
}

int32_t ffa_rx_acquire(struct domain *d)
{
    int32_t ret = FFA_RET_OK;
    struct ffa_ctx *ctx = d->arch.tee;

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
        ret = ffa_simple_call(FFA_RX_ACQUIRE, ffa_get_vm_id(d), 0, 0, 0);
        if ( ret != FFA_RET_OK )
            goto out;
    }
    ctx->rx_is_free = false;
out:
    spin_unlock(&ctx->rx_lock);

    return ret;
}

int32_t ffa_rx_release(struct domain *d)
{
    int32_t ret = FFA_RET_DENIED;
    struct ffa_ctx *ctx = d->arch.tee;

    spin_lock(&ctx->rx_lock);

    if ( !ctx->page_count || ctx->rx_is_free )
        goto out;

    if ( ffa_fw_supports_fid(FFA_RX_ACQUIRE) )
    {
        ret = ffa_simple_call(FFA_RX_RELEASE, ffa_get_vm_id(d), 0, 0, 0);
        if ( ret != FFA_RET_OK )
            goto out;
    }
    ret = FFA_RET_OK;
    ctx->rx_is_free = true;
out:
    spin_unlock(&ctx->rx_lock);

    return ret;
}

void ffa_rxtx_domain_destroy(struct domain *d)
{
    rxtx_unmap(d);
}

void ffa_rxtx_destroy(void)
{
    bool need_unmap = ffa_tx && ffa_rx;

    if ( ffa_tx )
    {
        free_xenheap_pages(ffa_tx, 0);
        ffa_tx = NULL;
    }
    if ( ffa_rx )
    {
        free_xenheap_pages(ffa_rx, 0);
        ffa_rx = NULL;
    }

    if ( need_unmap )
        ffa_rxtx_unmap(0);
}

bool ffa_rxtx_init(void)
{
    int e;

    /* Firmware not there or not supporting */
    if ( !ffa_fw_supports_fid(FFA_RXTX_MAP_64) )
        return false;

    ffa_rx = alloc_xenheap_pages(get_order_from_pages(FFA_RXTX_PAGE_COUNT), 0);
    if ( !ffa_rx )
        return false;

    ffa_tx = alloc_xenheap_pages(get_order_from_pages(FFA_RXTX_PAGE_COUNT), 0);
    if ( !ffa_tx )
        goto err;

    e = ffa_rxtx_map(__pa(ffa_tx), __pa(ffa_rx), FFA_RXTX_PAGE_COUNT);
    if ( e )
        goto err;

    return true;

err:
    ffa_rxtx_destroy();

    return false;
}
