#include <assert.h>

#include "xc_sr_common_x86_pv.h"

static xen_pfn_t pfn_to_mfn(const struct xc_sr_context *ctx, xen_pfn_t pfn)
{
    assert(pfn <= ctx->x86_pv.max_pfn);

    return xc_pfn_to_mfn(pfn, ctx->x86_pv.p2m, ctx->x86_pv.width);
}

/*
 * Expand our local tracking information for the p2m table and domains maximum
 * size.  Normally this will be called once to expand from 0 to max_pfn, but
 * is liable to expand multiple times if the domain grows on the sending side
 * after migration has started.
 */
static int expand_p2m(struct xc_sr_context *ctx, unsigned long max_pfn)
{
    xc_interface *xch = ctx->xch;
    unsigned long old_max = ctx->x86_pv.max_pfn, i;
    unsigned int fpp = PAGE_SIZE / ctx->x86_pv.width;
    unsigned long end_frame = (max_pfn / fpp) + 1;
    unsigned long old_end_frame = (old_max / fpp) + 1;
    xen_pfn_t *p2m = NULL, *p2m_pfns = NULL;
    uint32_t *pfn_types = NULL;
    size_t p2msz, p2m_pfnsz, pfn_typesz;

    assert(max_pfn > old_max);

    p2msz = (max_pfn + 1) * ctx->x86_pv.width;
    p2m = realloc(ctx->x86_pv.p2m, p2msz);
    if ( !p2m )
    {
        ERROR("Failed to (re)alloc %zu bytes for p2m", p2msz);
        return -1;
    }
    ctx->x86_pv.p2m = p2m;

    pfn_typesz = (max_pfn + 1) * sizeof(*pfn_types);
    pfn_types = realloc(ctx->x86_pv.restore.pfn_types, pfn_typesz);
    if ( !pfn_types )
    {
        ERROR("Failed to (re)alloc %zu bytes for pfn_types", pfn_typesz);
        return -1;
    }
    ctx->x86_pv.restore.pfn_types = pfn_types;

    p2m_pfnsz = (end_frame + 1) * sizeof(*p2m_pfns);
    p2m_pfns = realloc(ctx->x86_pv.p2m_pfns, p2m_pfnsz);
    if ( !p2m_pfns )
    {
        ERROR("Failed to (re)alloc %zu bytes for p2m frame list", p2m_pfnsz);
        return -1;
    }
    ctx->x86_pv.p2m_frames = end_frame;
    ctx->x86_pv.p2m_pfns = p2m_pfns;

    ctx->x86_pv.max_pfn = max_pfn;
    for ( i = (old_max ? old_max + 1 : 0); i <= max_pfn; ++i )
    {
        ctx->restore.ops.set_gfn(ctx, i, INVALID_MFN);
        ctx->restore.ops.set_page_type(ctx, i, 0);
    }

    for ( i = (old_end_frame ? old_end_frame + 1 : 0); i <= end_frame; ++i )
        ctx->x86_pv.p2m_pfns[i] = INVALID_MFN;

    DPRINTF("Changed max_pfn from %#lx to %#lx", old_max, max_pfn);
    return 0;
}

/*
 * Pin all of the pagetables.
 */
static int pin_pagetables(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    unsigned long i, nr_pins;
    struct mmuext_op pin[MAX_PIN_BATCH];

    for ( i = nr_pins = 0; i <= ctx->x86_pv.max_pfn; ++i )
    {
        if ( (ctx->x86_pv.restore.pfn_types[i] &
              XEN_DOMCTL_PFINFO_LPINTAB) == 0 )
            continue;

        switch ( (ctx->x86_pv.restore.pfn_types[i] &
                  XEN_DOMCTL_PFINFO_LTABTYPE_MASK) )
        {
        case XEN_DOMCTL_PFINFO_L1TAB:
            pin[nr_pins].cmd = MMUEXT_PIN_L1_TABLE;
            break;
        case XEN_DOMCTL_PFINFO_L2TAB:
            pin[nr_pins].cmd = MMUEXT_PIN_L2_TABLE;
            break;
        case XEN_DOMCTL_PFINFO_L3TAB:
            pin[nr_pins].cmd = MMUEXT_PIN_L3_TABLE;
            break;
        case XEN_DOMCTL_PFINFO_L4TAB:
            pin[nr_pins].cmd = MMUEXT_PIN_L4_TABLE;
            break;
        default:
            continue;
        }

        pin[nr_pins].arg1.mfn = pfn_to_mfn(ctx, i);
        nr_pins++;

        if ( nr_pins == MAX_PIN_BATCH )
        {
            if ( xc_mmuext_op(xch, pin, nr_pins, ctx->domid) != 0 )
            {
                PERROR("Failed to pin batch of pagetables");
                return -1;
            }
            nr_pins = 0;
        }
    }

    if ( (nr_pins > 0) && (xc_mmuext_op(xch, pin, nr_pins, ctx->domid) < 0) )
    {
        PERROR("Failed to pin batch of pagetables");
        return -1;
    }

    return 0;
}

/*
 * Update details in a guests start_info structure.
 */
static int process_start_info(struct xc_sr_context *ctx,
                              vcpu_guest_context_any_t *vcpu)
{
    xc_interface *xch = ctx->xch;
    xen_pfn_t pfn, mfn;
    start_info_any_t *guest_start_info = NULL;
    int rc = -1;

    pfn = GET_FIELD(vcpu, user_regs.edx, ctx->x86_pv.width);

    if ( pfn > ctx->x86_pv.max_pfn )
    {
        ERROR("Start Info pfn %#lx out of range", pfn);
        goto err;
    }
    else if ( ctx->x86_pv.restore.pfn_types[pfn] != XEN_DOMCTL_PFINFO_NOTAB )
    {
        ERROR("Start Info pfn %#lx has bad type %u", pfn,
              (ctx->x86_pv.restore.pfn_types[pfn] >>
               XEN_DOMCTL_PFINFO_LTAB_SHIFT));
        goto err;
    }

    mfn = pfn_to_mfn(ctx, pfn);
    if ( !mfn_in_pseudophysmap(ctx, mfn) )
    {
        ERROR("Start Info has bad mfn");
        dump_bad_pseudophysmap_entry(ctx, mfn);
        goto err;
    }

    SET_FIELD(vcpu, user_regs.edx, mfn, ctx->x86_pv.width);
    guest_start_info = xc_map_foreign_range(
        xch, ctx->domid, PAGE_SIZE, PROT_READ | PROT_WRITE, mfn);
    if ( !guest_start_info )
    {
        PERROR("Failed to map Start Info at mfn %#lx", mfn);
        goto err;
    }

    /* Deal with xenstore stuff */
    pfn = GET_FIELD(guest_start_info, store_mfn, ctx->x86_pv.width);
    if ( pfn > ctx->x86_pv.max_pfn )
    {
        ERROR("XenStore pfn %#lx out of range", pfn);
        goto err;
    }

    mfn = pfn_to_mfn(ctx, pfn);
    if ( !mfn_in_pseudophysmap(ctx, mfn) )
    {
        ERROR("XenStore pfn has bad mfn");
        dump_bad_pseudophysmap_entry(ctx, mfn);
        goto err;
    }

    ctx->restore.xenstore_gfn = mfn;
    SET_FIELD(guest_start_info, store_mfn, mfn, ctx->x86_pv.width);
    SET_FIELD(guest_start_info, store_evtchn,
              ctx->restore.xenstore_evtchn, ctx->x86_pv.width);

    /* Deal with console stuff */
    pfn = GET_FIELD(guest_start_info, console.domU.mfn, ctx->x86_pv.width);
    if ( pfn > ctx->x86_pv.max_pfn )
    {
        ERROR("Console pfn %#lx out of range", pfn);
        goto err;
    }

    mfn = pfn_to_mfn(ctx, pfn);
    if ( !mfn_in_pseudophysmap(ctx, mfn) )
    {
        ERROR("Console pfn has bad mfn");
        dump_bad_pseudophysmap_entry(ctx, mfn);
        goto err;
    }

    ctx->restore.console_gfn = mfn;
    SET_FIELD(guest_start_info, console.domU.mfn, mfn, ctx->x86_pv.width);
    SET_FIELD(guest_start_info, console.domU.evtchn,
              ctx->restore.console_evtchn, ctx->x86_pv.width);

    /* Set other information */
    SET_FIELD(guest_start_info, nr_pages,
              ctx->x86_pv.max_pfn + 1, ctx->x86_pv.width);
    SET_FIELD(guest_start_info, shared_info,
              ctx->dominfo.shared_info_frame << PAGE_SHIFT, ctx->x86_pv.width);
    SET_FIELD(guest_start_info, flags, 0, ctx->x86_pv.width);

    rc = 0;

err:
    if ( guest_start_info )
        munmap(guest_start_info, PAGE_SIZE);

    return rc;
}

/*
 * Process one stashed vcpu worth of basic state and send to Xen.
 */
static int process_vcpu_basic(struct xc_sr_context *ctx,
                              unsigned int vcpuid)
{
    xc_interface *xch = ctx->xch;
    vcpu_guest_context_any_t vcpu;
    xen_pfn_t pfn, mfn;
    unsigned i, gdt_count;
    int rc = -1;

    memcpy(&vcpu, ctx->x86_pv.restore.vcpus[vcpuid].basic,
           ctx->x86_pv.restore.vcpus[vcpuid].basicsz);

    /* Vcpu 0 is special: Convert the suspend record to an mfn. */
    if ( vcpuid == 0 )
    {
        rc = process_start_info(ctx, &vcpu);
        if ( rc )
            return rc;
        rc = -1;
    }

    SET_FIELD(&vcpu, flags,
              GET_FIELD(&vcpu, flags, ctx->x86_pv.width) | VGCF_online,
              ctx->x86_pv.width);

    gdt_count = GET_FIELD(&vcpu, gdt_ents, ctx->x86_pv.width);
    if ( gdt_count > FIRST_RESERVED_GDT_ENTRY )
    {
        ERROR("GDT entry count (%u) out of range (max %u)",
              gdt_count, FIRST_RESERVED_GDT_ENTRY);
        errno = ERANGE;
        goto err;
    }
    gdt_count = (gdt_count + 511) / 512; /* gdt_count now in units of frames. */

    /* Convert GDT frames to mfns. */
    for ( i = 0; i < gdt_count; ++i )
    {
        pfn = GET_FIELD(&vcpu, gdt_frames[i], ctx->x86_pv.width);
        if ( pfn > ctx->x86_pv.max_pfn )
        {
            ERROR("GDT frame %u (pfn %#lx) out of range", i, pfn);
            goto err;
        }
        else if ( (ctx->x86_pv.restore.pfn_types[pfn] !=
                   XEN_DOMCTL_PFINFO_NOTAB) )
        {
            ERROR("GDT frame %u (pfn %#lx) has bad type %u", i, pfn,
                  (ctx->x86_pv.restore.pfn_types[pfn] >>
                   XEN_DOMCTL_PFINFO_LTAB_SHIFT));
            goto err;
        }

        mfn = pfn_to_mfn(ctx, pfn);
        if ( !mfn_in_pseudophysmap(ctx, mfn) )
        {
            ERROR("GDT frame %u has bad mfn", i);
            dump_bad_pseudophysmap_entry(ctx, mfn);
            goto err;
        }

        SET_FIELD(&vcpu, gdt_frames[i], mfn, ctx->x86_pv.width);
    }

    /* Convert CR3 to an mfn. */
    pfn = cr3_to_mfn(ctx, GET_FIELD(&vcpu, ctrlreg[3], ctx->x86_pv.width));
    if ( pfn > ctx->x86_pv.max_pfn )
    {
        ERROR("cr3 (pfn %#lx) out of range", pfn);
        goto err;
    }
    else if ( (ctx->x86_pv.restore.pfn_types[pfn] &
                XEN_DOMCTL_PFINFO_LTABTYPE_MASK) !=
              (((xen_pfn_t)ctx->x86_pv.levels) <<
               XEN_DOMCTL_PFINFO_LTAB_SHIFT) )
    {
        ERROR("cr3 (pfn %#lx) has bad type %u, expected %u", pfn,
              (ctx->x86_pv.restore.pfn_types[pfn] >>
               XEN_DOMCTL_PFINFO_LTAB_SHIFT),
              ctx->x86_pv.levels);
        goto err;
    }

    mfn = pfn_to_mfn(ctx, pfn);
    if ( !mfn_in_pseudophysmap(ctx, mfn) )
    {
        ERROR("cr3 has bad mfn");
        dump_bad_pseudophysmap_entry(ctx, mfn);
        goto err;
    }

    SET_FIELD(&vcpu, ctrlreg[3], mfn_to_cr3(ctx, mfn), ctx->x86_pv.width);

    /* 64bit guests: Convert CR1 (guest pagetables) to mfn. */
    if ( ctx->x86_pv.levels == 4 && (vcpu.x64.ctrlreg[1] & 1) )
    {
        pfn = vcpu.x64.ctrlreg[1] >> PAGE_SHIFT;

        if ( pfn > ctx->x86_pv.max_pfn )
        {
            ERROR("cr1 (pfn %#lx) out of range", pfn);
            goto err;
        }
        else if ( (ctx->x86_pv.restore.pfn_types[pfn] &
                   XEN_DOMCTL_PFINFO_LTABTYPE_MASK) !=
                  (((xen_pfn_t)ctx->x86_pv.levels) <<
                   XEN_DOMCTL_PFINFO_LTAB_SHIFT) )
        {
            ERROR("cr1 (pfn %#lx) has bad type %u, expected %u", pfn,
                  (ctx->x86_pv.restore.pfn_types[pfn] >>
                   XEN_DOMCTL_PFINFO_LTAB_SHIFT),
                  ctx->x86_pv.levels);
            goto err;
        }

        mfn = pfn_to_mfn(ctx, pfn);
        if ( !mfn_in_pseudophysmap(ctx, mfn) )
        {
            ERROR("cr1 has bad mfn");
            dump_bad_pseudophysmap_entry(ctx, mfn);
            goto err;
        }

        vcpu.x64.ctrlreg[1] = (uint64_t)mfn << PAGE_SHIFT;
    }

    if ( xc_vcpu_setcontext(xch, ctx->domid, vcpuid, &vcpu) )
    {
        PERROR("Failed to set vcpu%u's basic info", vcpuid);
        goto err;
    }

    rc = 0;

 err:
    return rc;
}

/*
 * Process one stashed vcpu worth of extended state and send to Xen.
 */
static int process_vcpu_extended(struct xc_sr_context *ctx,
                                 unsigned int vcpuid)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_x86_pv_restore_vcpu *vcpu =
        &ctx->x86_pv.restore.vcpus[vcpuid];
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_set_ext_vcpucontext;
    domctl.domain = ctx->domid;
    memcpy(&domctl.u.ext_vcpucontext, vcpu->extd, vcpu->extdsz);

    if ( xc_domctl(xch, &domctl) != 0 )
    {
        PERROR("Failed to set vcpu%u's extended info", vcpuid);
        return -1;
    }

    return 0;
}

/*
 * Process one stashed vcpu worth of xsave state and send to Xen.
 */
static int process_vcpu_xsave(struct xc_sr_context *ctx,
                              unsigned int vcpuid)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_x86_pv_restore_vcpu *vcpu =
        &ctx->x86_pv.restore.vcpus[vcpuid];
    int rc;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BUFFER(void, buffer);

    buffer = xc_hypercall_buffer_alloc(xch, buffer, vcpu->xsavesz);
    if ( !buffer )
    {
        ERROR("Unable to allocate %zu bytes for xsave hypercall buffer",
              vcpu->xsavesz);
        return -1;
    }

    domctl.cmd = XEN_DOMCTL_setvcpuextstate;
    domctl.domain = ctx->domid;
    domctl.u.vcpuextstate.vcpu = vcpuid;
    domctl.u.vcpuextstate.size = vcpu->xsavesz;
    set_xen_guest_handle(domctl.u.vcpuextstate.buffer, buffer);

    memcpy(buffer, vcpu->xsave, vcpu->xsavesz);

    rc = xc_domctl(xch, &domctl);
    if ( rc )
        PERROR("Failed to set vcpu%u's xsave info", vcpuid);

    xc_hypercall_buffer_free(xch, buffer);

    return rc;
}

/*
 * Process one stashed vcpu worth of msr state and send to Xen.
 */
static int process_vcpu_msrs(struct xc_sr_context *ctx,
                             unsigned int vcpuid)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_x86_pv_restore_vcpu *vcpu =
        &ctx->x86_pv.restore.vcpus[vcpuid];
    int rc;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BUFFER(void, buffer);

    buffer = xc_hypercall_buffer_alloc(xch, buffer, vcpu->msrsz);
    if ( !buffer )
    {
        ERROR("Unable to allocate %zu bytes for msr hypercall buffer",
              vcpu->msrsz);
        return -1;
    }

    domctl.cmd = XEN_DOMCTL_set_vcpu_msrs;
    domctl.domain = ctx->domid;
    domctl.u.vcpu_msrs.vcpu = vcpuid;
    domctl.u.vcpu_msrs.msr_count = vcpu->msrsz % sizeof(xen_domctl_vcpu_msr_t);
    set_xen_guest_handle(domctl.u.vcpuextstate.buffer, buffer);

    memcpy(buffer, vcpu->msr, vcpu->msrsz);

    rc = xc_domctl(xch, &domctl);
    if ( rc )
        PERROR("Failed to set vcpu%u's msrs", vcpuid);

    xc_hypercall_buffer_free(xch, buffer);

    return rc;
}

/*
 * Process all stashed vcpu context and send to Xen.
 */
static int update_vcpu_context(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_x86_pv_restore_vcpu *vcpu;
    unsigned i;
    int rc = 0;

    for ( i = 0; i < ctx->x86_pv.restore.nr_vcpus; ++i )
    {
        vcpu = &ctx->x86_pv.restore.vcpus[i];

        if ( vcpu->basic )
        {
            rc = process_vcpu_basic(ctx, i);
            if ( rc )
                return rc;
        }
        else if ( i == 0 )
        {
            ERROR("Sender didn't send vcpu0's basic state");
            return -1;
        }

        if ( vcpu->extd )
        {
            rc = process_vcpu_extended(ctx, i);
            if ( rc )
                return rc;
        }

        if ( vcpu->xsave )
        {
            rc = process_vcpu_xsave(ctx, i);
            if ( rc )
                return rc;
        }

        if ( vcpu->msr )
        {
            rc = process_vcpu_msrs(ctx, i);
            if ( rc )
                return rc;
        }
    }

    return rc;
}

/*
 * Copy the p2m which has been constructed locally as memory has been
 * allocated, over the p2m in guest, so the guest can find its memory again on
 * resume.
 */
static int update_guest_p2m(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    xen_pfn_t mfn, pfn, *guest_p2m = NULL;
    unsigned i;
    int rc = -1;

    for ( i = 0; i < ctx->x86_pv.p2m_frames; ++i )
    {
        pfn = ctx->x86_pv.p2m_pfns[i];

        if ( pfn > ctx->x86_pv.max_pfn )
        {
            ERROR("pfn (%#lx) for p2m_frame_list[%u] out of range",
                  pfn, i);
            goto err;
        }
        else if ( (ctx->x86_pv.restore.pfn_types[pfn] !=
                   XEN_DOMCTL_PFINFO_NOTAB) )
        {
            ERROR("pfn (%#lx) for p2m_frame_list[%u] has bad type %u", pfn, i,
                  (ctx->x86_pv.restore.pfn_types[pfn] >>
                   XEN_DOMCTL_PFINFO_LTAB_SHIFT));
            goto err;
        }

        mfn = pfn_to_mfn(ctx, pfn);
        if ( !mfn_in_pseudophysmap(ctx, mfn) )
        {
            ERROR("p2m_frame_list[%u] has bad mfn", i);
            dump_bad_pseudophysmap_entry(ctx, mfn);
            goto err;
        }

        ctx->x86_pv.p2m_pfns[i] = mfn;
    }

    guest_p2m = xc_map_foreign_pages(xch, ctx->domid, PROT_WRITE,
                                     ctx->x86_pv.p2m_pfns,
                                     ctx->x86_pv.p2m_frames );
    if ( !guest_p2m )
    {
        PERROR("Failed to map p2m frames");
        goto err;
    }

    memcpy(guest_p2m, ctx->x86_pv.p2m,
           (ctx->x86_pv.max_pfn + 1) * ctx->x86_pv.width);
    rc = 0;
 err:
    if ( guest_p2m )
        munmap(guest_p2m, ctx->x86_pv.p2m_frames * PAGE_SIZE);

    return rc;
}

/*
 * Process an X86_PV_INFO record.
 */
static int handle_x86_pv_info(struct xc_sr_context *ctx,
                              struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_x86_pv_info *info = rec->data;

    if ( ctx->x86_pv.restore.seen_pv_info )
    {
        ERROR("Already received X86_PV_INFO record");
        return -1;
    }

    if ( rec->length < sizeof(*info) )
    {
        ERROR("X86_PV_INFO record truncated: length %u, expected %zu",
              rec->length, sizeof(*info));
        return -1;
    }
    else if ( info->guest_width != 4 &&
              info->guest_width != 8 )
    {
        ERROR("Unexpected guest width %u, Expected 4 or 8",
              info->guest_width);
        return -1;
    }
    else if ( info->guest_width != ctx->x86_pv.width )
    {
        int rc;
        struct xen_domctl domctl;

        /* Try to set address size, domain is always created 64 bit. */
        memset(&domctl, 0, sizeof(domctl));
        domctl.domain = ctx->domid;
        domctl.cmd    = XEN_DOMCTL_set_address_size;
        domctl.u.address_size.size = info->guest_width * 8;
        rc = do_domctl(xch, &domctl);
        if ( rc != 0 )
        {
            ERROR("Width of guest in stream (%u"
                  " bits) differs with existing domain (%u bits)",
                  info->guest_width * 8, ctx->x86_pv.width * 8);
            return -1;
        }

        /* Domain's information changed, better to refresh. */
        rc = x86_pv_domain_info(ctx);
        if ( rc != 0 )
        {
            ERROR("Unable to refresh guest information");
            return -1;
        }
    }
    else if ( info->pt_levels != 3 &&
              info->pt_levels != 4 )
    {
        ERROR("Unexpected guest levels %u, Expected 3 or 4",
              info->pt_levels);
        return -1;
    }
    else if ( info->pt_levels != ctx->x86_pv.levels )
    {
        ERROR("Levels of guest in stream (%u"
              ") differs with existing domain (%u)",
              info->pt_levels, ctx->x86_pv.levels);
        return -1;
    }

    ctx->x86_pv.restore.seen_pv_info = true;
    return 0;
}

/*
 * Process an X86_PV_P2M_FRAMES record.  Takes care of expanding the local p2m
 * state if needed.
 */
static int handle_x86_pv_p2m_frames(struct xc_sr_context *ctx,
                                    struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_x86_pv_p2m_frames *data = rec->data;
    unsigned start, end, x, fpp = PAGE_SIZE / ctx->x86_pv.width;
    int rc;

    if ( !ctx->x86_pv.restore.seen_pv_info )
    {
        ERROR("Not yet received X86_PV_INFO record");
        return -1;
    }

    if ( rec->length < sizeof(*data) )
    {
        ERROR("X86_PV_P2M_FRAMES record truncated: length %u, min %zu",
              rec->length, sizeof(*data) + sizeof(uint64_t));
        return -1;
    }
    else if ( data->start_pfn > data->end_pfn )
    {
        ERROR("End pfn in stream (%#x) exceeds Start (%#x)",
              data->end_pfn, data->start_pfn);
        return -1;
    }

    start =  data->start_pfn / fpp;
    end = data->end_pfn / fpp + 1;

    if ( rec->length != sizeof(*data) + ((end - start) * sizeof(uint64_t)) )
    {
        ERROR("X86_PV_P2M_FRAMES record wrong size: start_pfn %#x"
              ", end_pfn %#x, length %u, expected %zu + (%u - %u) * %zu",
              data->start_pfn, data->end_pfn, rec->length,
              sizeof(*data), end, start, sizeof(uint64_t));
        return -1;
    }

    if ( data->end_pfn > ctx->x86_pv.max_pfn )
    {
        rc = expand_p2m(ctx, data->end_pfn);
        if ( rc )
            return rc;
    }

    for ( x = 0; x < (end - start); ++x )
        ctx->x86_pv.p2m_pfns[start + x] = data->p2m_pfns[x];

    return 0;
}

/*
 * Processes X86_PV_VCPU_{BASIC,EXTENDED,XSAVE,MSRS} records from the stream.
 * The blobs are all stashed to one side as they need to be deferred until the
 * very end of the stream, rather than being send to Xen at the point they
 * arrive in the stream.  It performs all pre-hypercall size validation.
 */
static int handle_x86_pv_vcpu_blob(struct xc_sr_context *ctx,
                                   struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_x86_pv_vcpu_hdr *vhdr = rec->data;
    struct xc_sr_x86_pv_restore_vcpu *vcpu;
    const char *rec_name;
    size_t blobsz;
    void *blob;
    int rc = -1;

    switch ( rec->type )
    {
    case REC_TYPE_X86_PV_VCPU_BASIC:
        rec_name = "X86_PV_VCPU_BASIC";
        break;

    case REC_TYPE_X86_PV_VCPU_EXTENDED:
        rec_name = "X86_PV_VCPU_EXTENDED";
        break;

    case REC_TYPE_X86_PV_VCPU_XSAVE:
        rec_name = "X86_PV_VCPU_XSAVE";
        break;

    case REC_TYPE_X86_PV_VCPU_MSRS:
        rec_name = "X86_PV_VCPU_MSRS";
        break;

    default:
        ERROR("Unrecognised vcpu blob record %s (%u)",
              rec_type_to_str(rec->type), rec->type);
        goto out;
    }

    /* Confirm that there is a complete header. */
    if ( rec->length < sizeof(*vhdr) )
    {
        ERROR("%s record truncated: length %u, header size %zu",
              rec_name, rec->length, sizeof(*vhdr));
        goto out;
    }

    blobsz = rec->length - sizeof(*vhdr);

    /*
     * Tolerate empty records.  Older sending sides used to accidentally
     * generate them.
     */
    if ( blobsz == 0 )
    {
        DBGPRINTF("Skipping empty %s record for vcpu %u\n",
                  rec_type_to_str(rec->type), vhdr->vcpu_id);
        goto out;
    }

    /* Check that the vcpu id is within range. */
    if ( vhdr->vcpu_id >= ctx->x86_pv.restore.nr_vcpus )
    {
        ERROR("%s record vcpu_id (%u) exceeds domain max (%u)",
              rec_name, vhdr->vcpu_id, ctx->x86_pv.restore.nr_vcpus - 1);
        goto out;
    }

    vcpu = &ctx->x86_pv.restore.vcpus[vhdr->vcpu_id];

    /* Further per-record checks, where possible. */
    switch ( rec->type )
    {
    case REC_TYPE_X86_PV_VCPU_BASIC:
    {
        size_t vcpusz = ctx->x86_pv.width == 8 ?
            sizeof(vcpu_guest_context_x86_64_t) :
            sizeof(vcpu_guest_context_x86_32_t);

        if ( blobsz != vcpusz )
        {
            ERROR("%s record wrong size: expected %zu, got %u",
                  rec_name, sizeof(*vhdr) + vcpusz, rec->length);
            goto out;
        }
        break;
    }

    case REC_TYPE_X86_PV_VCPU_EXTENDED:
        if ( blobsz > 128 )
        {
            ERROR("%s record too long: max %zu, got %u",
                  rec_name, sizeof(*vhdr) + 128, rec->length);
            goto out;
        }
        break;

    case REC_TYPE_X86_PV_VCPU_XSAVE:
        if ( blobsz % sizeof(xen_domctl_vcpu_msr_t) != 0 )
        {
            ERROR("%s record payload size %zu expected to be a multiple of %zu",
                  rec_name, blobsz, sizeof(xen_domctl_vcpu_msr_t));
            goto out;
        }
        break;
    }

    /* Allocate memory. */
    blob = malloc(blobsz);
    if ( !blob )
    {
        ERROR("Unable to allocate %zu bytes for vcpu%u %s blob",
              blobsz, vhdr->vcpu_id, rec_name);
        goto out;
    }

    memcpy(blob, &vhdr->context, blobsz);

    /* Stash sideways for later. */
    switch ( rec->type )
    {
#define RECSTORE(x, y) case REC_TYPE_X86_PV_ ## x: \
        free(y); (y) = blob; (y ## sz) = blobsz; break

        RECSTORE(VCPU_BASIC,    vcpu->basic);
        RECSTORE(VCPU_EXTENDED, vcpu->extd);
        RECSTORE(VCPU_XSAVE,    vcpu->xsave);
        RECSTORE(VCPU_MSRS,     vcpu->msr);
#undef RECSTORE
    }

    rc = 0;

 out:
    return rc;
}

/*
 * Process a SHARED_INFO record from the stream.
 */
static int handle_shared_info(struct xc_sr_context *ctx,
                              struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    unsigned i;
    int rc = -1;
    shared_info_any_t *guest_shinfo = NULL;
    const shared_info_any_t *old_shinfo = rec->data;

    if ( !ctx->x86_pv.restore.seen_pv_info )
    {
        ERROR("Not yet received X86_PV_INFO record");
        return -1;
    }

    if ( rec->length != PAGE_SIZE )
    {
        ERROR("X86_PV_SHARED_INFO record wrong size: length %u"
              ", expected 4096", rec->length);
        goto err;
    }

    guest_shinfo = xc_map_foreign_range(
        xch, ctx->domid, PAGE_SIZE, PROT_READ | PROT_WRITE,
        ctx->dominfo.shared_info_frame);
    if ( !guest_shinfo )
    {
        PERROR("Failed to map Shared Info at mfn %#lx",
               ctx->dominfo.shared_info_frame);
        goto err;
    }

    MEMCPY_FIELD(guest_shinfo, old_shinfo, vcpu_info, ctx->x86_pv.width);
    MEMCPY_FIELD(guest_shinfo, old_shinfo, arch, ctx->x86_pv.width);

    SET_FIELD(guest_shinfo, arch.pfn_to_mfn_frame_list_list,
              0, ctx->x86_pv.width);

    MEMSET_ARRAY_FIELD(guest_shinfo, evtchn_pending, 0, ctx->x86_pv.width);
    for ( i = 0; i < XEN_LEGACY_MAX_VCPUS; i++ )
        SET_FIELD(guest_shinfo, vcpu_info[i].evtchn_pending_sel,
                  0, ctx->x86_pv.width);

    MEMSET_ARRAY_FIELD(guest_shinfo, evtchn_mask, 0xff, ctx->x86_pv.width);

    rc = 0;
 err:

    if ( guest_shinfo )
        munmap(guest_shinfo, PAGE_SIZE);

    return rc;
}

/* restore_ops function. */
static bool x86_pv_pfn_is_valid(const struct xc_sr_context *ctx, xen_pfn_t pfn)
{
    return pfn <= ctx->x86_pv.max_pfn;
}

/* restore_ops function. */
static void x86_pv_set_page_type(struct xc_sr_context *ctx, xen_pfn_t pfn,
                                 unsigned long type)
{
    assert(pfn <= ctx->x86_pv.max_pfn);

    ctx->x86_pv.restore.pfn_types[pfn] = type;
}

/* restore_ops function. */
static void x86_pv_set_gfn(struct xc_sr_context *ctx, xen_pfn_t pfn,
                           xen_pfn_t mfn)
{
    assert(pfn <= ctx->x86_pv.max_pfn);

    if ( ctx->x86_pv.width == sizeof(uint64_t) )
        /* 64 bit guest.  Need to expand INVALID_MFN for 32 bit toolstacks. */
        ((uint64_t *)ctx->x86_pv.p2m)[pfn] = mfn == INVALID_MFN ? ~0ULL : mfn;
    else
        /* 32 bit guest.  Can truncate INVALID_MFN for 64 bit toolstacks. */
        ((uint32_t *)ctx->x86_pv.p2m)[pfn] = mfn;
}

/*
 * restore_ops function.  Convert pfns back to mfns in pagetables.  Possibly
 * needs to populate new frames if a PTE is found referring to a frame which
 * hasn't yet been seen from PAGE_DATA records.
 */
static int x86_pv_localise_page(struct xc_sr_context *ctx,
                                uint32_t type, void *page)
{
    xc_interface *xch = ctx->xch;
    uint64_t *table = page;
    uint64_t pte;
    unsigned i, to_populate;
    xen_pfn_t pfns[(PAGE_SIZE / sizeof(uint64_t))];

    type &= XEN_DOMCTL_PFINFO_LTABTYPE_MASK;

    /* Only page tables need localisation. */
    if ( type < XEN_DOMCTL_PFINFO_L1TAB || type > XEN_DOMCTL_PFINFO_L4TAB )
        return 0;

    /* Check to see whether we need to populate any new frames. */
    for ( i = 0, to_populate = 0; i < (PAGE_SIZE / sizeof(uint64_t)); ++i )
    {
        pte = table[i];

        if ( pte & _PAGE_PRESENT )
        {
            xen_pfn_t pfn = pte_to_frame(pte);

#ifdef __i386__
            if ( pfn == INVALID_MFN )
            {
                ERROR("PTE truncation detected.  L%u[%u] = %016"PRIx64,
                      type >> XEN_DOMCTL_PFINFO_LTAB_SHIFT, i, pte);
                errno = E2BIG;
                return -1;
            }
#endif

            if ( pfn_to_mfn(ctx, pfn) == INVALID_MFN )
                pfns[to_populate++] = pfn;
        }
    }

    if ( to_populate && populate_pfns(ctx, to_populate, pfns, NULL) )
        return -1;

    for ( i = 0; i < (PAGE_SIZE / sizeof(uint64_t)); ++i )
    {
        pte = table[i];

        if ( pte & _PAGE_PRESENT )
        {
            xen_pfn_t mfn, pfn;

            pfn = pte_to_frame(pte);
            mfn = pfn_to_mfn(ctx, pfn);

            if ( !mfn_in_pseudophysmap(ctx, mfn) )
            {
                ERROR("Bad mfn for L%u[%u] - pte %"PRIx64,
                      type >> XEN_DOMCTL_PFINFO_LTAB_SHIFT, i, pte);
                dump_bad_pseudophysmap_entry(ctx, mfn);
                errno = ERANGE;
                return -1;
            }

            table[i] = merge_pte(pte, mfn);
        }
    }

    return 0;
}

/*
 * restore_ops function.  Confirm that the incoming stream matches the type of
 * domain we are attempting to restore into.
 */
static int x86_pv_setup(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc;

    if ( ctx->restore.guest_type != DHDR_TYPE_X86_PV )
    {
        ERROR("Unable to restore %s domain into an x86_pv domain",
              dhdr_type_to_str(ctx->restore.guest_type));
        return -1;
    }
    else if ( ctx->restore.guest_page_size != PAGE_SIZE )
    {
        ERROR("Invalid page size %d for x86_pv domains",
              ctx->restore.guest_page_size);
        return -1;
    }

    rc = x86_pv_domain_info(ctx);
    if ( rc )
        return rc;

    ctx->x86_pv.restore.nr_vcpus = ctx->dominfo.max_vcpu_id + 1;
    ctx->x86_pv.restore.vcpus = calloc(sizeof(struct xc_sr_x86_pv_restore_vcpu),
                                       ctx->x86_pv.restore.nr_vcpus);
    if ( !ctx->x86_pv.restore.vcpus )
    {
        errno = ENOMEM;
        return -1;
    }

    rc = x86_pv_map_m2p(ctx);
    if ( rc )
        return rc;

    return rc;
}

/*
 * restore_ops function.
 */
static int x86_pv_process_record(struct xc_sr_context *ctx,
                                 struct xc_sr_record *rec)
{
    switch ( rec->type )
    {
    case REC_TYPE_X86_PV_INFO:
        return handle_x86_pv_info(ctx, rec);

    case REC_TYPE_X86_PV_P2M_FRAMES:
        return handle_x86_pv_p2m_frames(ctx, rec);

    case REC_TYPE_X86_PV_VCPU_BASIC:
    case REC_TYPE_X86_PV_VCPU_EXTENDED:
    case REC_TYPE_X86_PV_VCPU_XSAVE:
    case REC_TYPE_X86_PV_VCPU_MSRS:
        return handle_x86_pv_vcpu_blob(ctx, rec);

    case REC_TYPE_SHARED_INFO:
        return handle_shared_info(ctx, rec);

    case REC_TYPE_TSC_INFO:
        return handle_tsc_info(ctx, rec);

    default:
        return RECORD_NOT_PROCESSED;
    }
}

/*
 * restore_ops function.  Update the vcpu context in Xen, pin the pagetables,
 * rewrite the p2m and seed the grant table.
 */
static int x86_pv_stream_complete(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc;

    rc = update_vcpu_context(ctx);
    if ( rc )
        return rc;

    rc = pin_pagetables(ctx);
    if ( rc )
        return rc;

    rc = update_guest_p2m(ctx);
    if ( rc )
        return rc;

    rc = xc_dom_gnttab_seed(xch, ctx->domid,
                            ctx->restore.console_gfn,
                            ctx->restore.xenstore_gfn,
                            ctx->restore.console_domid,
                            ctx->restore.xenstore_domid);
    if ( rc )
    {
        PERROR("Failed to seed grant table");
        return rc;
    }

    return rc;
}

/*
 * restore_ops function.
 */
static int x86_pv_cleanup(struct xc_sr_context *ctx)
{
    free(ctx->x86_pv.p2m);
    free(ctx->x86_pv.p2m_pfns);

    if ( ctx->x86_pv.restore.vcpus )
    {
        unsigned i;

        for ( i = 0; i < ctx->x86_pv.restore.nr_vcpus; ++i )
        {
            struct xc_sr_x86_pv_restore_vcpu *vcpu =
                &ctx->x86_pv.restore.vcpus[i];

            free(vcpu->basic);
            free(vcpu->extd);
            free(vcpu->xsave);
            free(vcpu->msr);
        }

        free(ctx->x86_pv.restore.vcpus);
    }

    free(ctx->x86_pv.restore.pfn_types);

    if ( ctx->x86_pv.m2p )
        munmap(ctx->x86_pv.m2p, ctx->x86_pv.nr_m2p_frames * PAGE_SIZE);

    return 0;
}

struct xc_sr_restore_ops restore_ops_x86_pv =
{
    .pfn_is_valid    = x86_pv_pfn_is_valid,
    .pfn_to_gfn      = pfn_to_mfn,
    .set_page_type   = x86_pv_set_page_type,
    .set_gfn         = x86_pv_set_gfn,
    .localise_page   = x86_pv_localise_page,
    .setup           = x86_pv_setup,
    .process_record  = x86_pv_process_record,
    .stream_complete = x86_pv_stream_complete,
    .cleanup         = x86_pv_cleanup,
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
