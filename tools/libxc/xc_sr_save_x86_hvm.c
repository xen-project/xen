#include <assert.h>

#include "xc_sr_common_x86.h"

#include <xen/hvm/params.h>

/*
 * Query for the HVM context and write an HVM_CONTEXT record into the stream.
 */
static int write_hvm_context(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc, hvm_buf_size;
    struct xc_sr_record hvm_rec =
    {
        .type = REC_TYPE_HVM_CONTEXT,
    };

    hvm_buf_size = xc_domain_hvm_getcontext(xch, ctx->domid, 0, 0);
    if ( hvm_buf_size < 0 )
    {
        PERROR("Couldn't get HVM context size from Xen");
        rc = -1;
        goto out;
    }

    hvm_rec.data = malloc(hvm_buf_size);
    if ( !hvm_rec.data )
    {
        PERROR("Couldn't allocate memory");
        rc = -1;
        goto out;
    }

    hvm_buf_size = xc_domain_hvm_getcontext(xch, ctx->domid,
                                            hvm_rec.data, hvm_buf_size);
    if ( hvm_buf_size < 0 )
    {
        PERROR("Couldn't get HVM context from Xen");
        rc = -1;
        goto out;
    }

    hvm_rec.length = hvm_buf_size;
    rc = write_record(ctx, &hvm_rec);
    if ( rc < 0 )
    {
        PERROR("error write HVM_CONTEXT record");
        goto out;
    }

 out:
    free(hvm_rec.data);
    return rc;
}

/*
 * Query for a range of HVM parameters and write an HVM_PARAMS record into the
 * stream.
 */
static int write_hvm_params(struct xc_sr_context *ctx)
{
    static const unsigned int params[] = {
        HVM_PARAM_STORE_PFN,
        HVM_PARAM_IOREQ_PFN,
        HVM_PARAM_BUFIOREQ_PFN,
        HVM_PARAM_PAGING_RING_PFN,
        HVM_PARAM_MONITOR_RING_PFN,
        HVM_PARAM_SHARING_RING_PFN,
        HVM_PARAM_VM86_TSS,
        HVM_PARAM_CONSOLE_PFN,
        HVM_PARAM_ACPI_IOPORTS_LOCATION,
        HVM_PARAM_VIRIDIAN,
        HVM_PARAM_IDENT_PT,
        HVM_PARAM_PAE_ENABLED,
        HVM_PARAM_VM_GENERATION_ID_ADDR,
        HVM_PARAM_IOREQ_SERVER_PFN,
        HVM_PARAM_NR_IOREQ_SERVER_PAGES,
    };

    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_hvm_params_entry entries[ARRAY_SIZE(params)];
    struct xc_sr_rec_hvm_params hdr = {
        .count = 0,
    };
    struct xc_sr_record rec = {
        .type   = REC_TYPE_HVM_PARAMS,
        .length = sizeof(hdr),
        .data   = &hdr,
    };
    unsigned int i;
    int rc;

    for ( i = 0; i < ARRAY_SIZE(params); i++ )
    {
        uint32_t index = params[i];
        uint64_t value;

        rc = xc_hvm_param_get(xch, ctx->domid, index, &value);
        if ( rc )
        {
            PERROR("Failed to get HVMPARAM at index %u", index);
            return rc;
        }

        if ( value != 0 )
        {
            entries[hdr.count].index = index;
            entries[hdr.count].value = value;
            hdr.count++;
        }
    }

    rc = write_split_record(ctx, &rec, entries, hdr.count * sizeof(*entries));
    if ( rc )
        PERROR("Failed to write HVM_PARAMS record");

    return rc;
}

static xen_pfn_t x86_hvm_pfn_to_gfn(const struct xc_sr_context *ctx,
                                    xen_pfn_t pfn)
{
    /* identity map */
    return pfn;
}

static int x86_hvm_normalise_page(struct xc_sr_context *ctx,
                                  xen_pfn_t type, void **page)
{
    /* no-op */
    return 0;
}

static int x86_hvm_setup(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;

    if ( ctx->save.callbacks->switch_qemu_logdirty(
             ctx->domid, 1, ctx->save.callbacks->data) )
    {
        PERROR("Couldn't enable qemu log-dirty mode");
        return -1;
    }

    ctx->x86_hvm.save.qemu_enabled_logdirty = true;

    return 0;
}

static int x86_hvm_start_of_stream(struct xc_sr_context *ctx)
{
    /* no-op */
    return 0;
}

static int x86_hvm_start_of_checkpoint(struct xc_sr_context *ctx)
{
    /* no-op */
    return 0;
}

static int x86_hvm_end_of_checkpoint(struct xc_sr_context *ctx)
{
    int rc;

    /* Write the TSC record. */
    rc = write_tsc_info(ctx);
    if ( rc )
        return rc;

    /* Write the HVM_CONTEXT record. */
    rc = write_hvm_context(ctx);
    if ( rc )
        return rc;

    /* Write HVM_PARAMS record contains applicable HVM params. */
    rc = write_hvm_params(ctx);
    if ( rc )
        return rc;

    return 0;
}

static int x86_hvm_cleanup(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;

    /* If qemu successfully enabled logdirty mode, attempt to disable. */
    if ( ctx->x86_hvm.save.qemu_enabled_logdirty &&
         ctx->save.callbacks->switch_qemu_logdirty(
             ctx->domid, 0, ctx->save.callbacks->data) )
    {
        PERROR("Couldn't disable qemu log-dirty mode");
        return -1;
    }

    return 0;
}

struct xc_sr_save_ops save_ops_x86_hvm =
{
    .pfn_to_gfn          = x86_hvm_pfn_to_gfn,
    .normalise_page      = x86_hvm_normalise_page,
    .setup               = x86_hvm_setup,
    .start_of_stream     = x86_hvm_start_of_stream,
    .start_of_checkpoint = x86_hvm_start_of_checkpoint,
    .end_of_checkpoint   = x86_hvm_end_of_checkpoint,
    .cleanup             = x86_hvm_cleanup,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
