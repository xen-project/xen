#include <assert.h>
#include <arpa/inet.h>

#include "xc_sr_common_x86.h"

#ifdef XG_LIBXL_HVM_COMPAT
static int handle_toolstack(struct xc_sr_context *ctx, struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    int rc;

    if ( !ctx->restore.callbacks || !ctx->restore.callbacks->toolstack_restore )
        return 0;

    rc = ctx->restore.callbacks->toolstack_restore(
        ctx->domid, rec->data, rec->length, ctx->restore.callbacks->data);

    if ( rc < 0 )
        PERROR("restoring toolstack");
    return rc;
}
#endif

/*
 * Process an HVM_CONTEXT record from the stream.
 */
static int handle_hvm_context(struct xc_sr_context *ctx,
                              struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    void *p;

    p = malloc(rec->length);
    if ( !p )
    {
        ERROR("Unable to allocate %u bytes for hvm context", rec->length);
        return -1;
    }

    free(ctx->x86_hvm.restore.context);

    ctx->x86_hvm.restore.context = memcpy(p, rec->data, rec->length);
    ctx->x86_hvm.restore.contextsz = rec->length;

    return 0;
}

/*
 * Process an HVM_PARAMS record from the stream.
 */
static int handle_hvm_params(struct xc_sr_context *ctx,
                             struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_hvm_params *hdr = rec->data;
    struct xc_sr_rec_hvm_params_entry *entry = hdr->param;
    unsigned int i;
    int rc;

    if ( rec->length < sizeof(*hdr)
         || rec->length < sizeof(*hdr) + hdr->count * sizeof(*entry) )
    {
        ERROR("hvm_params record is too short");
        return -1;
    }

    for ( i = 0; i < hdr->count; i++, entry++ )
    {
        switch ( entry->index )
        {
        case HVM_PARAM_CONSOLE_PFN:
            ctx->restore.console_gfn = entry->value;
            xc_clear_domain_page(xch, ctx->domid, entry->value);
            break;
        case HVM_PARAM_STORE_PFN:
            ctx->restore.xenstore_gfn = entry->value;
            xc_clear_domain_page(xch, ctx->domid, entry->value);
            break;
        case HVM_PARAM_IOREQ_PFN:
        case HVM_PARAM_BUFIOREQ_PFN:
            xc_clear_domain_page(xch, ctx->domid, entry->value);
            break;
        }

        rc = xc_hvm_param_set(xch, ctx->domid, entry->index, entry->value);
        if ( rc < 0 )
        {
            PERROR("set HVM param %"PRId64" = 0x%016"PRIx64,
                   entry->index, entry->value);
            return rc;
        }
    }
    return 0;
}

#ifdef XG_LIBXL_HVM_COMPAT
int read_qemu(struct xc_sr_context *ctx);
int read_qemu(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    char qemusig[21];
    uint32_t qlen;
    void *qbuf = NULL;
    int rc = -1;

    if ( read_exact(ctx->fd, qemusig, sizeof(qemusig)) )
    {
        PERROR("Error reading QEMU signature");
        goto out;
    }

    if ( !memcmp(qemusig, "DeviceModelRecord0002", sizeof(qemusig)) )
    {
        if ( read_exact(ctx->fd, &qlen, sizeof(qlen)) )
        {
            PERROR("Error reading QEMU record length");
            goto out;
        }

        qbuf = malloc(qlen);
        if ( !qbuf )
        {
            PERROR("no memory for device model state");
            goto out;
        }

        if ( read_exact(ctx->fd, qbuf, qlen) )
        {
            PERROR("Error reading device model state");
            goto out;
        }
    }
    else
    {
        ERROR("Invalid device model state signature '%*.*s'",
              (int)sizeof(qemusig), (int)sizeof(qemusig), qemusig);
        goto out;
    }

    /* With Remus, this could be read many times */
    if ( ctx->x86_hvm.restore.qbuf )
        free(ctx->x86_hvm.restore.qbuf);
    ctx->x86_hvm.restore.qbuf = qbuf;
    ctx->x86_hvm.restore.qlen = qlen;
    rc = 0;

out:
    if (rc)
        free(qbuf);
    return rc;
}

static int handle_qemu(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    char path[256];
    uint32_t qlen = ctx->x86_hvm.restore.qlen;
    void *qbuf = ctx->x86_hvm.restore.qbuf;
    int rc = -1;
    FILE *fp = NULL;

    sprintf(path, XC_DEVICE_MODEL_RESTORE_FILE".%u", ctx->domid);
    fp = fopen(path, "wb");
    if ( !fp )
    {
        PERROR("Failed to open '%s' for writing", path);
        goto out;
    }

    DPRINTF("Writing %u bytes of QEMU data", qlen);
    if ( fwrite(qbuf, 1, qlen, fp) != qlen )
    {
        PERROR("Failed to write %u bytes of QEMU data", qlen);
        goto out;
    }

    rc = 0;

 out:
    if ( fp )
        fclose(fp);
    free(qbuf);

    return rc;
}
#endif

/* restore_ops function. */
static bool x86_hvm_pfn_is_valid(const struct xc_sr_context *ctx, xen_pfn_t pfn)
{
    return true;
}

/* restore_ops function. */
static xen_pfn_t x86_hvm_pfn_to_gfn(const struct xc_sr_context *ctx,
                                    xen_pfn_t pfn)
{
    return pfn;
}

/* restore_ops function. */
static void x86_hvm_set_gfn(struct xc_sr_context *ctx, xen_pfn_t pfn,
                            xen_pfn_t gfn)
{
    /* no op */
}

/* restore_ops function. */
static void x86_hvm_set_page_type(struct xc_sr_context *ctx,
                                  xen_pfn_t pfn, xen_pfn_t type)
{
    /* no-op */
}

/* restore_ops function. */
static int x86_hvm_localise_page(struct xc_sr_context *ctx,
                                 uint32_t type, void *page)
{
    /* no-op */
    return 0;
}

/*
 * restore_ops function. Confirms the stream matches the domain.
 */
static int x86_hvm_setup(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;

    if ( ctx->restore.guest_type != DHDR_TYPE_X86_HVM )
    {
        ERROR("Unable to restore %s domain into an x86_hvm domain",
              dhdr_type_to_str(ctx->restore.guest_type));
        return -1;
    }
    else if ( ctx->restore.guest_page_size != PAGE_SIZE )
    {
        ERROR("Invalid page size %u for x86_hvm domains",
              ctx->restore.guest_page_size);
        return -1;
    }

    return 0;
}

/*
 * restore_ops function.
 */
static int x86_hvm_process_record(struct xc_sr_context *ctx,
                                  struct xc_sr_record *rec)
{
    switch ( rec->type )
    {
    case REC_TYPE_TSC_INFO:
        return handle_tsc_info(ctx, rec);

    case REC_TYPE_HVM_CONTEXT:
        return handle_hvm_context(ctx, rec);

    case REC_TYPE_HVM_PARAMS:
        return handle_hvm_params(ctx, rec);

#ifdef XG_LIBXL_HVM_COMPAT
    case REC_TYPE_TOOLSTACK:
        return handle_toolstack(ctx, rec);
#endif

    default:
        return RECORD_NOT_PROCESSED;
    }
}

/*
 * restore_ops function.  Sets extra hvm parameters and seeds the grant table.
 */
static int x86_hvm_stream_complete(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc;

    rc = xc_hvm_param_set(xch, ctx->domid, HVM_PARAM_STORE_EVTCHN,
                          ctx->restore.xenstore_evtchn);
    if ( rc )
    {
        PERROR("Failed to set HVM_PARAM_STORE_EVTCHN");
        return rc;
    }

    rc = xc_hvm_param_set(xch, ctx->domid, HVM_PARAM_CONSOLE_EVTCHN,
                          ctx->restore.console_evtchn);
    if ( rc )
    {
        PERROR("Failed to set HVM_PARAM_CONSOLE_EVTCHN");
        return rc;
    }

    rc = xc_domain_hvm_setcontext(xch, ctx->domid,
                                  ctx->x86_hvm.restore.context,
                                  ctx->x86_hvm.restore.contextsz);
    if ( rc < 0 )
    {
        PERROR("Unable to restore HVM context");
        return rc;
    }

    rc = xc_dom_gnttab_hvm_seed(xch, ctx->domid,
                                ctx->restore.console_gfn,
                                ctx->restore.xenstore_gfn,
                                ctx->restore.console_domid,
                                ctx->restore.xenstore_domid);
    if ( rc )
    {
        PERROR("Failed to seed grant table");
        return rc;
    }

#ifdef XG_LIBXL_HVM_COMPAT
    rc = handle_qemu(ctx);
    if ( rc )
    {
        ERROR("Failed to dump qemu");
        return rc;
    }
#endif

    return rc;
}

static int x86_hvm_cleanup(struct xc_sr_context *ctx)
{
    free(ctx->x86_hvm.restore.context);

    return 0;
}

struct xc_sr_restore_ops restore_ops_x86_hvm =
{
    .pfn_is_valid    = x86_hvm_pfn_is_valid,
    .pfn_to_gfn      = x86_hvm_pfn_to_gfn,
    .set_gfn         = x86_hvm_set_gfn,
    .set_page_type   = x86_hvm_set_page_type,
    .localise_page   = x86_hvm_localise_page,
    .setup           = x86_hvm_setup,
    .process_record  = x86_hvm_process_record,
    .stream_complete = x86_hvm_stream_complete,
    .cleanup         = x86_hvm_cleanup,
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
