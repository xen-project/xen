#include "xc_sr_common_x86.h"

int write_x86_tsc_info(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_x86_tsc_info tsc = {};
    struct xc_sr_record rec = {
        .type = REC_TYPE_X86_TSC_INFO,
        .length = sizeof(tsc),
        .data = &tsc,
    };

    if ( xc_domain_get_tsc_info(xch, ctx->domid, &tsc.mode,
                                &tsc.nsec, &tsc.khz, &tsc.incarnation) < 0 )
    {
        PERROR("Unable to obtain TSC information");
        return -1;
    }

    return write_record(ctx, &rec);
}

int handle_x86_tsc_info(struct xc_sr_context *ctx, struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_x86_tsc_info *tsc = rec->data;

    if ( rec->length != sizeof(*tsc) )
    {
        ERROR("X86_TSC_INFO record wrong size: length %u, expected %zu",
              rec->length, sizeof(*tsc));
        return -1;
    }

    if ( xc_domain_set_tsc_info(xch, ctx->domid, tsc->mode,
                                tsc->nsec, tsc->khz, tsc->incarnation) )
    {
        PERROR("Unable to set TSC information");
        return -1;
    }

    return 0;
}

int write_x86_cpu_policy_records(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_record cpuid = { .type = REC_TYPE_X86_CPUID_POLICY, };
    struct xc_sr_record msrs  = { .type = REC_TYPE_X86_MSR_POLICY, };
    uint32_t nr_leaves = 0, nr_msrs = 0;
    int rc;

    if ( xc_get_cpu_policy_size(xch, &nr_leaves, &nr_msrs) < 0 )
    {
        PERROR("Unable to get CPU Policy size");
        return -1;
    }

    cpuid.data = malloc(nr_leaves * sizeof(xen_cpuid_leaf_t));
    msrs.data  = malloc(nr_msrs   * sizeof(xen_msr_entry_t));
    if ( !cpuid.data || !msrs.data )
    {
        ERROR("Cannot allocate memory for CPU Policy");
        rc = -1;
        goto out;
    }

    if ( xc_get_domain_cpu_policy(xch, ctx->domid, &nr_leaves, cpuid.data,
                                  &nr_msrs, msrs.data) )
    {
        PERROR("Unable to get d%d CPU Policy", ctx->domid);
        rc = -1;
        goto out;
    }

    cpuid.length = nr_leaves * sizeof(xen_cpuid_leaf_t);
    if ( cpuid.length )
    {
        rc = write_record(ctx, &cpuid);
        if ( rc )
            goto out;
    }

    msrs.length = nr_msrs * sizeof(xen_msr_entry_t);
    if ( msrs.length )
        rc = write_record(ctx, &msrs);

 out:
    free(cpuid.data);
    free(msrs.data);

    return rc;
}

int handle_x86_cpuid_policy(struct xc_sr_context *ctx, struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    int rc;

    if ( rec->length == 0 ||
         rec->length % sizeof(xen_cpuid_leaf_t) != 0 )
    {
        ERROR("X86_CPUID_POLICY size %u should be multiple of %zu",
              rec->length, sizeof(xen_cpuid_leaf_t));
        return -1;
    }

    rc = update_blob(&ctx->x86.restore.cpuid, rec->data, rec->length);
    if ( rc )
        ERROR("Unable to allocate %u bytes for X86_CPUID_POLICY", rec->length);

    return rc;
}

int handle_x86_msr_policy(struct xc_sr_context *ctx, struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    int rc;

    if ( rec->length == 0 ||
         rec->length % sizeof(xen_msr_entry_t) != 0 )
    {
        ERROR("X86_MSR_POLICY size %u should be multiple of %zu",
              rec->length, sizeof(xen_cpuid_leaf_t));
        return -1;
    }

    rc = update_blob(&ctx->x86.restore.msr, rec->data, rec->length);
    if ( rc )
        ERROR("Unable to allocate %u bytes for X86_MSR_POLICY", rec->length);

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
