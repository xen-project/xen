#include "xc_sr_common.h"

/*
 * Is a pfn populated?
 */
static bool pfn_is_populated(const struct xc_sr_context *ctx, xen_pfn_t pfn)
{
    if ( pfn > ctx->restore.max_populated_pfn )
        return false;
    return test_bit(pfn, ctx->restore.populated_pfns);
}

/*
 * Set a pfn as populated, expanding the tracking structures if needed. To
 * avoid realloc()ing too excessivly, the size increased to the nearest power
 * of two large enough to contain the required pfn.
 */
static int pfn_set_populated(struct xc_sr_context *ctx, xen_pfn_t pfn)
{
    xc_interface *xch = ctx->xch;

    if ( pfn > ctx->restore.max_populated_pfn )
    {
        xen_pfn_t new_max;
        size_t old_sz, new_sz;
        unsigned long *p;

        /* Round up to the nearest power of two larger than pfn, less 1. */
        new_max = pfn;
        new_max |= new_max >> 1;
        new_max |= new_max >> 2;
        new_max |= new_max >> 4;
        new_max |= new_max >> 8;
        new_max |= new_max >> 16;
#ifdef __x86_64__
        new_max |= new_max >> 32;
#endif

        old_sz = bitmap_size(ctx->restore.max_populated_pfn + 1);
        new_sz = bitmap_size(new_max + 1);
        p = realloc(ctx->restore.populated_pfns, new_sz);
        if ( !p )
        {
            ERROR("Failed to realloc populated bitmap");
            errno = ENOMEM;
            return -1;
        }

        memset((uint8_t *)p + old_sz, 0x00, new_sz - old_sz);

        ctx->restore.populated_pfns    = p;
        ctx->restore.max_populated_pfn = new_max;
    }

    set_bit(pfn, ctx->restore.populated_pfns);

    return 0;
}

/*
 * Given a set of pfns, obtain memory from Xen to fill the physmap for the
 * unpopulated subset.  If types is NULL, no page typechecking is performed
 * and all unpopulated pfns are populated.
 */
int populate_pfns(struct xc_sr_context *ctx, unsigned count,
                  const xen_pfn_t *original_pfns, const uint32_t *types)
{
    xc_interface *xch = ctx->xch;
    xen_pfn_t *mfns = malloc(count * sizeof(*mfns)),
        *pfns = malloc(count * sizeof(*pfns));
    unsigned i, nr_pfns = 0;
    int rc = -1;

    if ( !mfns || !pfns )
    {
        ERROR("Failed to allocate %zu bytes for populating the physmap",
              2 * count * sizeof(*mfns));
        goto err;
    }

    for ( i = 0; i < count; ++i )
    {
        if ( (!types || (types &&
                         (types[i] != XEN_DOMCTL_PFINFO_XTAB &&
                          types[i] != XEN_DOMCTL_PFINFO_BROKEN))) &&
             !pfn_is_populated(ctx, original_pfns[i]) )
        {
            pfns[nr_pfns] = mfns[nr_pfns] = original_pfns[i];
            ++nr_pfns;
        }
    }

    if ( nr_pfns )
    {
        rc = xc_domain_populate_physmap_exact(
            xch, ctx->domid, nr_pfns, 0, 0, mfns);
        if ( rc )
        {
            PERROR("Failed to populate physmap");
            goto err;
        }

        for ( i = 0; i < nr_pfns; ++i )
        {
            if ( mfns[i] == INVALID_MFN )
            {
                ERROR("Populate physmap failed for pfn %u", i);
                rc = -1;
                goto err;
            }

            rc = pfn_set_populated(ctx, pfns[i]);
            if ( rc )
                goto err;
            ctx->restore.ops.set_gfn(ctx, pfns[i], mfns[i]);
        }
    }

    rc = 0;

 err:
    free(pfns);
    free(mfns);

    return rc;
}

int xc_domain_restore2(xc_interface *xch, int io_fd, uint32_t dom,
                       unsigned int store_evtchn, unsigned long *store_mfn,
                       domid_t store_domid, unsigned int console_evtchn,
                       unsigned long *console_mfn, domid_t console_domid,
                       unsigned int hvm, unsigned int pae, int superpages,
                       int checkpointed_stream,
                       struct restore_callbacks *callbacks)
{
    IPRINTF("In experimental %s", __func__);
    return -1;
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
