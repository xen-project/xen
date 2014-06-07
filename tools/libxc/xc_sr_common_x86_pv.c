#include <assert.h>

#include "xc_sr_common_x86_pv.h"

xen_pfn_t mfn_to_pfn(struct xc_sr_context *ctx, xen_pfn_t mfn)
{
    assert(mfn <= ctx->x86_pv.max_mfn);
    return ctx->x86_pv.m2p[mfn];
}

bool mfn_in_pseudophysmap(struct xc_sr_context *ctx, xen_pfn_t mfn)
{
    return ( (mfn <= ctx->x86_pv.max_mfn) &&
             (mfn_to_pfn(ctx, mfn) <= ctx->x86_pv.max_pfn) &&
             (xc_pfn_to_mfn(mfn_to_pfn(ctx, mfn), ctx->x86_pv.p2m,
                            ctx->x86_pv.width) == mfn) );
}

void dump_bad_pseudophysmap_entry(struct xc_sr_context *ctx, xen_pfn_t mfn)
{
    xc_interface *xch = ctx->xch;
    xen_pfn_t pfn = ~0UL;

    ERROR("mfn %#lx, max %#lx", mfn, ctx->x86_pv.max_mfn);

    if ( (mfn != ~0UL) && (mfn <= ctx->x86_pv.max_mfn) )
    {
        pfn = ctx->x86_pv.m2p[mfn];
        ERROR("  m2p[%#lx] = %#lx, max_pfn %#lx",
              mfn, pfn, ctx->x86_pv.max_pfn);
    }

    if ( (pfn != ~0UL) && (pfn <= ctx->x86_pv.max_pfn) )
        ERROR("  p2m[%#lx] = %#lx",
              pfn, xc_pfn_to_mfn(pfn, ctx->x86_pv.p2m, ctx->x86_pv.width));
}

xen_pfn_t cr3_to_mfn(struct xc_sr_context *ctx, uint64_t cr3)
{
    if ( ctx->x86_pv.width == 8 )
        return cr3 >> 12;
    else
    {
        /* 32bit guests can't represent mfns wider than 32 bits */
        if ( cr3 & 0xffffffff00000000UL )
            return ~0UL;
        else
            return (uint32_t)((cr3 >> 12) | (cr3 << 20));
    }
}

uint64_t mfn_to_cr3(struct xc_sr_context *ctx, xen_pfn_t _mfn)
{
    uint64_t mfn = _mfn;

    if ( ctx->x86_pv.width == 8 )
        return mfn << 12;
    else
    {
        /* 32bit guests can't represent mfns wider than 32 bits */
        if ( mfn & 0xffffffff00000000UL )
            return ~0UL;
        else
            return (uint32_t)((mfn << 12) | (mfn >> 20));
    }
}

int x86_pv_domain_info(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    unsigned int guest_width, guest_levels, fpp;
    xen_pfn_t max_pfn;

    /* Get the domain width */
    if ( xc_domain_get_guest_width(xch, ctx->domid, &guest_width) )
    {
        PERROR("Unable to determine dom%d's width", ctx->domid);
        return -1;
    }

    if ( guest_width == 4 )
        guest_levels = 3;
    else if ( guest_width == 8 )
        guest_levels = 4;
    else
    {
        ERROR("Invalid guest width %d.  Expected 32 or 64", guest_width * 8);
        return -1;
    }
    ctx->x86_pv.width = guest_width;
    ctx->x86_pv.levels = guest_levels;
    fpp = PAGE_SIZE / ctx->x86_pv.width;

    DPRINTF("%d bits, %d levels", guest_width * 8, guest_levels);

    /* Get the domain's size */
    if ( xc_domain_maximum_gpfn(xch, ctx->domid, &max_pfn) < 0 )
    {
        PERROR("Unable to obtain guests max pfn");
        return -1;
    }

    if ( max_pfn > 0 )
    {
        ctx->x86_pv.max_pfn = max_pfn;
        ctx->x86_pv.p2m_frames = (ctx->x86_pv.max_pfn + fpp) / fpp;

        DPRINTF("max_pfn %#lx, p2m_frames %d", max_pfn, ctx->x86_pv.p2m_frames);
    }

    return 0;
}

int x86_pv_map_m2p(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    xen_pfn_t m2p_chunks, m2p_size, max_page;
    privcmd_mmap_entry_t *entries = NULL;
    xen_pfn_t *extents_start = NULL;
    int rc = -1, i;

    if ( xc_maximum_ram_page(xch, &max_page) < 0 )
    {
        PERROR("Failed to get maximum ram page");
        goto err;
    }

    ctx->x86_pv.max_mfn = max_page;
    m2p_size   = M2P_SIZE(ctx->x86_pv.max_mfn);
    m2p_chunks = M2P_CHUNKS(ctx->x86_pv.max_mfn);

    extents_start = malloc(m2p_chunks * sizeof(xen_pfn_t));
    if ( !extents_start )
    {
        ERROR("Unable to allocate %lu bytes for m2p mfns",
              m2p_chunks * sizeof(xen_pfn_t));
        goto err;
    }

    if ( xc_machphys_mfn_list(xch, m2p_chunks, extents_start) )
    {
        PERROR("Failed to get m2p mfn list");
        goto err;
    }

    entries = malloc(m2p_chunks * sizeof(privcmd_mmap_entry_t));
    if ( !entries )
    {
        ERROR("Unable to allocate %lu bytes for m2p mapping mfns",
              m2p_chunks * sizeof(privcmd_mmap_entry_t));
        goto err;
    }

    for ( i = 0; i < m2p_chunks; ++i )
        entries[i].mfn = extents_start[i];

    ctx->x86_pv.m2p = xc_map_foreign_ranges(
        xch, DOMID_XEN, m2p_size, PROT_READ,
        M2P_CHUNK_SIZE, entries, m2p_chunks);

    if ( !ctx->x86_pv.m2p )
    {
        PERROR("Failed to mmap() m2p ranges");
        goto err;
    }

    ctx->x86_pv.nr_m2p_frames = (M2P_CHUNK_SIZE >> PAGE_SHIFT) * m2p_chunks;

#ifdef __i386__
    /* 32 bit toolstacks automatically get the compat m2p */
    ctx->x86_pv.compat_m2p_mfn0 = entries[0].mfn;
#else
    /* 64 bit toolstacks need to ask Xen specially for it */
    {
        struct xen_machphys_mfn_list xmml = {
            .max_extents = 1,
            .extent_start = { &ctx->x86_pv.compat_m2p_mfn0 }
        };

        rc = do_memory_op(xch, XENMEM_machphys_compat_mfn_list,
                          &xmml, sizeof(xmml));
        if ( rc || xmml.nr_extents != 1 )
        {
            PERROR("Failed to get compat mfn list from Xen");
            rc = -1;
            goto err;
        }
    }
#endif

    /* All Done */
    rc = 0;
    DPRINTF("max_mfn %#lx", ctx->x86_pv.max_mfn);

err:
    free(entries);
    free(extents_start);

    return rc;
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
