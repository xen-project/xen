#include <assert.h>
#include <limits.h>

#include "xc_sr_common_x86_pv.h"

/* Check a 64 bit virtual address for being canonical. */
static inline bool is_canonical_address(xen_vaddr_t vaddr)
{
    return ((int64_t)vaddr >> 47) == ((int64_t)vaddr >> 63);
}

/*
 * Maps the guests shared info page.
 */
static int map_shinfo(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;

    ctx->x86_pv.shinfo = xc_map_foreign_range(
        xch, ctx->domid, PAGE_SIZE, PROT_READ, ctx->dominfo.shared_info_frame);
    if ( !ctx->x86_pv.shinfo )
    {
        PERROR("Failed to map shared info frame at mfn %#lx",
               ctx->dominfo.shared_info_frame);
        return -1;
    }

    return 0;
}

/*
 * Copy a list of mfns from a guest, accounting for differences between guest
 * and toolstack width.  Can fail if truncation would occur.
 */
static int copy_mfns_from_guest(const struct xc_sr_context *ctx,
                                xen_pfn_t *dst, const void *src, size_t count)
{
    size_t x;

    if ( ctx->x86_pv.width == sizeof(unsigned long) )
        memcpy(dst, src, count * sizeof(*dst));
    else
    {
        for ( x = 0; x < count; ++x )
        {
#ifdef __x86_64__
            /* 64bit toolstack, 32bit guest.  Expand any INVALID_MFN. */
            uint32_t s = ((uint32_t *)src)[x];

            dst[x] = s == ~0U ? INVALID_MFN : s;
#else
            /*
             * 32bit toolstack, 64bit guest.  Truncate INVALID_MFN, but bail
             * if any other truncation would occur.
             *
             * This will only occur on hosts where a PV guest has ram above
             * the 16TB boundary.  A 32bit dom0 is unlikely to have
             * successfully booted on a system this large.
             */
            uint64_t s = ((uint64_t *)src)[x];

            if ( (s != ~0ULL) && ((s >> 32) != 0) )
            {
                errno = E2BIG;
                return -1;
            }

            dst[x] = s;
#endif
        }
    }

    return 0;
}

/*
 * Map the p2m leave pages and build an array of their pfns.
 */
static int map_p2m_leaves(struct xc_sr_context *ctx, xen_pfn_t *mfns,
                          size_t n_mfns)
{
    xc_interface *xch = ctx->xch;
    unsigned x;

    ctx->x86_pv.p2m = xc_map_foreign_pages(xch, ctx->domid, PROT_READ,
                                           mfns, n_mfns);
    if ( !ctx->x86_pv.p2m )
    {
        PERROR("Failed to map p2m frames");
        return -1;
    }

    ctx->save.p2m_size = ctx->x86_pv.max_pfn + 1;
    ctx->x86_pv.p2m_frames = n_mfns;
    ctx->x86_pv.p2m_pfns = malloc(n_mfns * sizeof(*mfns));
    if ( !ctx->x86_pv.p2m_pfns )
    {
        ERROR("Cannot allocate %zu bytes for p2m pfns list",
              n_mfns * sizeof(*mfns));
        return -1;
    }

    /* Convert leaf frames from mfns to pfns. */
    for ( x = 0; x < n_mfns; ++x )
    {
        if ( !mfn_in_pseudophysmap(ctx, mfns[x]) )
        {
            ERROR("Bad mfn in p2m_frame_list[%u]", x);
            dump_bad_pseudophysmap_entry(ctx, mfns[x]);
            errno = ERANGE;
            return -1;
        }

        ctx->x86_pv.p2m_pfns[x] = mfn_to_pfn(ctx, mfns[x]);
    }

    return 0;
}

/*
 * Walk the guests frame list list and frame list to identify and map the
 * frames making up the guests p2m table.  Construct a list of pfns making up
 * the table.
 */
static int map_p2m_tree(struct xc_sr_context *ctx)
{
    /* Terminology:
     *
     * fll   - frame list list, top level p2m, list of fl mfns
     * fl    - frame list, mid level p2m, list of leaf mfns
     * local - own allocated buffers, adjusted for bitness
     * guest - mappings into the domain
     */
    xc_interface *xch = ctx->xch;
    int rc = -1;
    unsigned x, saved_x, fpp, fll_entries, fl_entries;
    xen_pfn_t fll_mfn, saved_mfn, max_pfn;

    xen_pfn_t *local_fll = NULL;
    void *guest_fll = NULL;
    size_t local_fll_size;

    xen_pfn_t *local_fl = NULL;
    void *guest_fl = NULL;
    size_t local_fl_size;

    fpp = PAGE_SIZE / ctx->x86_pv.width;
    fll_entries = (ctx->x86_pv.max_pfn / (fpp * fpp)) + 1;
    if ( fll_entries > fpp )
    {
        ERROR("max_pfn %#lx too large for p2m tree", ctx->x86_pv.max_pfn);
        goto err;
    }

    fll_mfn = GET_FIELD(ctx->x86_pv.shinfo, arch.pfn_to_mfn_frame_list_list,
                        ctx->x86_pv.width);
    if ( fll_mfn == 0 || fll_mfn > ctx->x86_pv.max_mfn )
    {
        ERROR("Bad mfn %#lx for p2m frame list list", fll_mfn);
        goto err;
    }

    /* Map the guest top p2m. */
    guest_fll = xc_map_foreign_range(xch, ctx->domid, PAGE_SIZE,
                                     PROT_READ, fll_mfn);
    if ( !guest_fll )
    {
        PERROR("Failed to map p2m frame list list at %#lx", fll_mfn);
        goto err;
    }

    local_fll_size = fll_entries * sizeof(*local_fll);
    local_fll = malloc(local_fll_size);
    if ( !local_fll )
    {
        ERROR("Cannot allocate %zu bytes for local p2m frame list list",
              local_fll_size);
        goto err;
    }

    if ( copy_mfns_from_guest(ctx, local_fll, guest_fll, fll_entries) )
    {
        ERROR("Truncation detected copying p2m frame list list");
        goto err;
    }

    /* Check for bad mfns in frame list list. */
    saved_mfn = 0;
    saved_x = 0;
    for ( x = 0; x < fll_entries; ++x )
    {
        if ( local_fll[x] == 0 || local_fll[x] > ctx->x86_pv.max_mfn )
        {
            ERROR("Bad mfn %#lx at index %u (of %u) in p2m frame list list",
                  local_fll[x], x, fll_entries);
            goto err;
        }
        if ( local_fll[x] != saved_mfn )
        {
            saved_mfn = local_fll[x];
            saved_x = x;
        }
    }

    /*
     * Check for actual lower max_pfn:
     * If the trailing entries of the frame list list were all the same we can
     * assume they all reference mid pages all referencing p2m pages with all
     * invalid entries. Otherwise there would be multiple pfns referencing all
     * the same mfn which can't work across migration, as this sharing would be
     * broken by the migration process.
     * Adjust max_pfn if possible to avoid allocating much larger areas as
     * needed for p2m and logdirty map.
     */
    max_pfn = (saved_x + 1) * fpp * fpp - 1;
    if ( max_pfn < ctx->x86_pv.max_pfn )
    {
        ctx->x86_pv.max_pfn = max_pfn;
        fll_entries = (ctx->x86_pv.max_pfn / (fpp * fpp)) + 1;
    }
    ctx->x86_pv.p2m_frames = (ctx->x86_pv.max_pfn + fpp) / fpp;
    DPRINTF("max_pfn %#lx, p2m_frames %d", ctx->x86_pv.max_pfn,
            ctx->x86_pv.p2m_frames);
    fl_entries  = (ctx->x86_pv.max_pfn / fpp) + 1;

    /* Map the guest mid p2m frames. */
    guest_fl = xc_map_foreign_pages(xch, ctx->domid, PROT_READ,
                                    local_fll, fll_entries);
    if ( !guest_fl )
    {
        PERROR("Failed to map p2m frame list");
        goto err;
    }

    local_fl_size = fl_entries * sizeof(*local_fl);
    local_fl = malloc(local_fl_size);
    if ( !local_fl )
    {
        ERROR("Cannot allocate %zu bytes for local p2m frame list",
              local_fl_size);
        goto err;
    }

    if ( copy_mfns_from_guest(ctx, local_fl, guest_fl, fl_entries) )
    {
        ERROR("Truncation detected copying p2m frame list");
        goto err;
    }

    for ( x = 0; x < fl_entries; ++x )
    {
        if ( local_fl[x] == 0 || local_fl[x] > ctx->x86_pv.max_mfn )
        {
            ERROR("Bad mfn %#lx at index %u (of %u) in p2m frame list",
                  local_fl[x], x, fl_entries);
            goto err;
        }
    }

    /* Map the p2m leaves themselves. */
    rc = map_p2m_leaves(ctx, local_fl, fl_entries);

err:

    free(local_fl);
    if ( guest_fl )
        munmap(guest_fl, fll_entries * PAGE_SIZE);

    free(local_fll);
    if ( guest_fll )
        munmap(guest_fll, PAGE_SIZE);

    return rc;
}

/*
 * Get p2m_generation count.
 * Returns an error if the generation count has changed since the last call.
 */
static int get_p2m_generation(struct xc_sr_context *ctx)
{
    uint64_t p2m_generation;
    int rc;

    p2m_generation = GET_FIELD(ctx->x86_pv.shinfo, arch.p2m_generation,
                               ctx->x86_pv.width);

    rc = (p2m_generation == ctx->x86_pv.p2m_generation) ? 0 : -1;
    ctx->x86_pv.p2m_generation = p2m_generation;

    return rc;
}

static int x86_pv_check_vm_state_p2m_list(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc;

    if ( !ctx->save.live )
        return 0;

    rc = get_p2m_generation(ctx);
    if ( rc )
        ERROR("p2m generation count changed. Migration aborted.");

    return rc;
}

/*
 * Map the guest p2m frames specified via a cr3 value, a virtual address, and
 * the maximum pfn. PTE entries are 64 bits for both, 32 and 64 bit guests as
 * in 32 bit case we support PAE guests only.
 */
static int map_p2m_list(struct xc_sr_context *ctx, uint64_t p2m_cr3)
{
    xc_interface *xch = ctx->xch;
    xen_vaddr_t p2m_vaddr, p2m_end, mask, off;
    xen_pfn_t p2m_mfn, mfn, saved_mfn, max_pfn;
    uint64_t *ptes = NULL;
    xen_pfn_t *mfns = NULL;
    unsigned fpp, n_pages, level, shift, idx_start, idx_end, idx, saved_idx;
    int rc = -1;

    p2m_mfn = cr3_to_mfn(ctx, p2m_cr3);
    assert(p2m_mfn != 0);
    if ( p2m_mfn > ctx->x86_pv.max_mfn )
    {
        ERROR("Bad p2m_cr3 value %#" PRIx64, p2m_cr3);
        errno = ERANGE;
        goto err;
    }

    get_p2m_generation(ctx);

    p2m_vaddr = GET_FIELD(ctx->x86_pv.shinfo, arch.p2m_vaddr,
                          ctx->x86_pv.width);
    fpp = PAGE_SIZE / ctx->x86_pv.width;
    ctx->x86_pv.p2m_frames = ctx->x86_pv.max_pfn / fpp + 1;
    p2m_end = p2m_vaddr + ctx->x86_pv.p2m_frames * PAGE_SIZE - 1;

    if ( ctx->x86_pv.width == 8 )
    {
        mask = 0x0000ffffffffffffULL;
        if ( !is_canonical_address(p2m_vaddr) ||
             !is_canonical_address(p2m_end) ||
             p2m_end < p2m_vaddr ||
             (p2m_vaddr <= HYPERVISOR_VIRT_END_X86_64 &&
              p2m_end > HYPERVISOR_VIRT_START_X86_64) )
        {
            ERROR("Bad virtual p2m address range %#" PRIx64 "-%#" PRIx64,
                  p2m_vaddr, p2m_end);
            errno = ERANGE;
            goto err;
        }
    }
    else
    {
        mask = 0x00000000ffffffffULL;
        if ( p2m_vaddr > mask || p2m_end > mask || p2m_end < p2m_vaddr ||
             (p2m_vaddr <= HYPERVISOR_VIRT_END_X86_32 &&
              p2m_end > HYPERVISOR_VIRT_START_X86_32) )
        {
            ERROR("Bad virtual p2m address range %#" PRIx64 "-%#" PRIx64,
                  p2m_vaddr, p2m_end);
            errno = ERANGE;
            goto err;
        }
    }

    DPRINTF("p2m list from %#" PRIx64 " to %#" PRIx64 ", root at %#lx",
            p2m_vaddr, p2m_end, p2m_mfn);
    DPRINTF("max_pfn %#lx, p2m_frames %d", ctx->x86_pv.max_pfn,
            ctx->x86_pv.p2m_frames);

    mfns = malloc(sizeof(*mfns));
    if ( !mfns )
    {
        ERROR("Cannot allocate memory for array of %u mfns", 1);
        goto err;
    }
    mfns[0] = p2m_mfn;
    off = 0;
    saved_mfn = 0;
    idx_start = idx_end = saved_idx = 0;

    for ( level = ctx->x86_pv.levels; level > 0; level-- )
    {
        n_pages = idx_end - idx_start + 1;
        ptes = xc_map_foreign_pages(xch, ctx->domid, PROT_READ, mfns, n_pages);
        if ( !ptes )
        {
            PERROR("Failed to map %u page table pages for p2m list", n_pages);
            goto err;
        }
        free(mfns);

        shift = level * 9 + 3;
        idx_start = ((p2m_vaddr - off) & mask) >> shift;
        idx_end = ((p2m_end - off) & mask) >> shift;
        idx = idx_end - idx_start + 1;
        mfns = malloc(sizeof(*mfns) * idx);
        if ( !mfns )
        {
            ERROR("Cannot allocate memory for array of %u mfns", idx);
            goto err;
        }

        for ( idx = idx_start; idx <= idx_end; idx++ )
        {
            mfn = pte_to_frame(ptes[idx]);
            if ( mfn == 0 || mfn > ctx->x86_pv.max_mfn )
            {
                ERROR("Bad mfn %#lx during page table walk for vaddr %#" PRIx64 " at level %d of p2m list",
                      mfn, off + ((xen_vaddr_t)idx << shift), level);
                errno = ERANGE;
                goto err;
            }
            mfns[idx - idx_start] = mfn;

            /* Maximum pfn check at level 2. Same reasoning as for p2m tree. */
            if ( level == 2 )
            {
                if ( mfn != saved_mfn )
                {
                    saved_mfn = mfn;
                    saved_idx = idx - idx_start;
                }
            }
        }

        if ( level == 2 )
        {
            if ( saved_idx == idx_end )
                saved_idx++;
            max_pfn = ((xen_pfn_t)saved_idx << 9) * fpp - 1;
            if ( max_pfn < ctx->x86_pv.max_pfn )
            {
                ctx->x86_pv.max_pfn = max_pfn;
                ctx->x86_pv.p2m_frames = (ctx->x86_pv.max_pfn + fpp) / fpp;
                p2m_end = p2m_vaddr + ctx->x86_pv.p2m_frames * PAGE_SIZE - 1;
                idx_end = idx_start + saved_idx;
            }
        }

        munmap(ptes, n_pages * PAGE_SIZE);
        ptes = NULL;
        off = p2m_vaddr & ((mask >> shift) << shift);
    }

    /* Map the p2m leaves themselves. */
    rc = map_p2m_leaves(ctx, mfns, idx_end - idx_start + 1);

err:
    free(mfns);
    if ( ptes )
        munmap(ptes, n_pages * PAGE_SIZE);

    return rc;
}

/*
 * Map the guest p2m frames.
 * Depending on guest support this might either be a virtual mapped linear
 * list (preferred format) or a 3 level tree linked via mfns.
 */
static int map_p2m(struct xc_sr_context *ctx)
{
    uint64_t p2m_cr3;

    ctx->x86_pv.p2m_generation = ~0ULL;
    ctx->x86_pv.max_pfn = GET_FIELD(ctx->x86_pv.shinfo, arch.max_pfn,
                                    ctx->x86_pv.width) - 1;
    p2m_cr3 = GET_FIELD(ctx->x86_pv.shinfo, arch.p2m_cr3, ctx->x86_pv.width);

    return p2m_cr3 ? map_p2m_list(ctx, p2m_cr3) : map_p2m_tree(ctx);
}

/*
 * Obtain a specific vcpus basic state and write an X86_PV_VCPU_BASIC record
 * into the stream.  Performs mfn->pfn conversion on architectural state.
 */
static int write_one_vcpu_basic(struct xc_sr_context *ctx, uint32_t id)
{
    xc_interface *xch = ctx->xch;
    xen_pfn_t mfn, pfn;
    unsigned i, gdt_count;
    int rc = -1;
    vcpu_guest_context_any_t vcpu;
    struct xc_sr_rec_x86_pv_vcpu_hdr vhdr =
    {
        .vcpu_id = id,
    };
    struct xc_sr_record rec =
    {
        .type = REC_TYPE_X86_PV_VCPU_BASIC,
        .length = sizeof(vhdr),
        .data = &vhdr,
    };

    if ( xc_vcpu_getcontext(xch, ctx->domid, id, &vcpu) )
    {
        PERROR("Failed to get vcpu%u context", id);
        goto err;
    }

    /* Vcpu0 is special: Convert the suspend record to a pfn. */
    if ( id == 0 )
    {
        mfn = GET_FIELD(&vcpu, user_regs.edx, ctx->x86_pv.width);
        if ( !mfn_in_pseudophysmap(ctx, mfn) )
        {
            ERROR("Bad mfn for suspend record");
            dump_bad_pseudophysmap_entry(ctx, mfn);
            errno = ERANGE;
            goto err;
        }
        SET_FIELD(&vcpu, user_regs.edx, mfn_to_pfn(ctx, mfn),
                  ctx->x86_pv.width);
    }

    gdt_count = GET_FIELD(&vcpu, gdt_ents, ctx->x86_pv.width);
    if ( gdt_count > FIRST_RESERVED_GDT_ENTRY )
    {
        ERROR("GDT entry count (%u) out of range (max %u)",
              gdt_count, FIRST_RESERVED_GDT_ENTRY);
        errno = ERANGE;
        goto err;
    }
    gdt_count = (gdt_count + 511) / 512; /* gdt_count now in units of frames. */

    /* Convert GDT frames to pfns. */
    for ( i = 0; i < gdt_count; ++i )
    {
        mfn = GET_FIELD(&vcpu, gdt_frames[i], ctx->x86_pv.width);
        if ( !mfn_in_pseudophysmap(ctx, mfn) )
        {
            ERROR("Bad mfn for frame %u of vcpu%u's GDT", i, id);
            dump_bad_pseudophysmap_entry(ctx, mfn);
            errno = ERANGE;
            goto err;
        }
        SET_FIELD(&vcpu, gdt_frames[i], mfn_to_pfn(ctx, mfn),
                  ctx->x86_pv.width);
    }

    /* Convert CR3 to a pfn. */
    mfn = cr3_to_mfn(ctx, GET_FIELD(&vcpu, ctrlreg[3], ctx->x86_pv.width));
    if ( !mfn_in_pseudophysmap(ctx, mfn) )
    {
        ERROR("Bad mfn for vcpu%u's cr3", id);
        dump_bad_pseudophysmap_entry(ctx, mfn);
        errno = ERANGE;
        goto err;
    }
    pfn = mfn_to_pfn(ctx, mfn);
    SET_FIELD(&vcpu, ctrlreg[3], mfn_to_cr3(ctx, pfn), ctx->x86_pv.width);

    /* 64bit guests: Convert CR1 (guest pagetables) to pfn. */
    if ( ctx->x86_pv.levels == 4 && vcpu.x64.ctrlreg[1] )
    {
        mfn = vcpu.x64.ctrlreg[1] >> PAGE_SHIFT;
        if ( !mfn_in_pseudophysmap(ctx, mfn) )
        {
            ERROR("Bad mfn for vcpu%u's cr1", id);
            dump_bad_pseudophysmap_entry(ctx, mfn);
            errno = ERANGE;
            goto err;
        }
        pfn = mfn_to_pfn(ctx, mfn);
        vcpu.x64.ctrlreg[1] = 1 | ((uint64_t)pfn << PAGE_SHIFT);
    }

    if ( ctx->x86_pv.width == 8 )
        rc = write_split_record(ctx, &rec, &vcpu, sizeof(vcpu.x64));
    else
        rc = write_split_record(ctx, &rec, &vcpu, sizeof(vcpu.x32));

 err:
    return rc;
}

/*
 * Obtain a specific vcpus extended state and write an X86_PV_VCPU_EXTENDED
 * record into the stream.
 */
static int write_one_vcpu_extended(struct xc_sr_context *ctx, uint32_t id)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_x86_pv_vcpu_hdr vhdr =
    {
        .vcpu_id = id,
    };
    struct xc_sr_record rec =
    {
        .type = REC_TYPE_X86_PV_VCPU_EXTENDED,
        .length = sizeof(vhdr),
        .data = &vhdr,
    };
    struct xen_domctl domctl =
    {
        .cmd = XEN_DOMCTL_get_ext_vcpucontext,
        .domain = ctx->domid,
        .u.ext_vcpucontext.vcpu = id,
    };

    if ( xc_domctl(xch, &domctl) < 0 )
    {
        PERROR("Unable to get vcpu%u extended context", id);
        return -1;
    }

    /* No content? Skip the record. */
    if ( domctl.u.ext_vcpucontext.size == 0 )
        return 0;

    return write_split_record(ctx, &rec, &domctl.u.ext_vcpucontext,
                              domctl.u.ext_vcpucontext.size);
}

/*
 * Query to see whether a specific vcpu has xsave state and if so, write an
 * X86_PV_VCPU_XSAVE record into the stream.
 */
static int write_one_vcpu_xsave(struct xc_sr_context *ctx, uint32_t id)
{
    xc_interface *xch = ctx->xch;
    int rc = -1;
    DECLARE_HYPERCALL_BUFFER(void, buffer);
    struct xc_sr_rec_x86_pv_vcpu_hdr vhdr =
    {
        .vcpu_id = id,
    };
    struct xc_sr_record rec =
    {
        .type = REC_TYPE_X86_PV_VCPU_XSAVE,
        .length = sizeof(vhdr),
        .data = &vhdr,
    };
    struct xen_domctl domctl =
    {
        .cmd = XEN_DOMCTL_getvcpuextstate,
        .domain = ctx->domid,
        .u.vcpuextstate.vcpu = id,
    };

    if ( xc_domctl(xch, &domctl) < 0 )
    {
        PERROR("Unable to get vcpu%u's xsave context", id);
        goto err;
    }

    /* No xsave state? skip this record. */
    if ( !domctl.u.vcpuextstate.xfeature_mask )
        goto out;

    buffer = xc_hypercall_buffer_alloc(xch, buffer, domctl.u.vcpuextstate.size);
    if ( !buffer )
    {
        ERROR("Unable to allocate %"PRIx64" bytes for vcpu%u's xsave context",
              domctl.u.vcpuextstate.size, id);
        goto err;
    }

    set_xen_guest_handle(domctl.u.vcpuextstate.buffer, buffer);
    if ( xc_domctl(xch, &domctl) < 0 )
    {
        PERROR("Unable to get vcpu%u's xsave context", id);
        goto err;
    }

    /* No xsave state? Skip this record. */
    if ( domctl.u.vcpuextstate.size == 0 )
        goto out;

    rc = write_split_record(ctx, &rec, buffer, domctl.u.vcpuextstate.size);
    if ( rc )
        goto err;

 out:
    rc = 0;

 err:
    xc_hypercall_buffer_free(xch, buffer);

    return rc;
}

/*
 * Query to see whether a specific vcpu has msr state and if so, write an
 * X86_PV_VCPU_MSRS record into the stream.
 */
static int write_one_vcpu_msrs(struct xc_sr_context *ctx, uint32_t id)
{
    xc_interface *xch = ctx->xch;
    int rc = -1;
    size_t buffersz;
    DECLARE_HYPERCALL_BUFFER(void, buffer);
    struct xc_sr_rec_x86_pv_vcpu_hdr vhdr =
    {
        .vcpu_id = id,
    };
    struct xc_sr_record rec =
    {
        .type = REC_TYPE_X86_PV_VCPU_MSRS,
        .length = sizeof(vhdr),
        .data = &vhdr,
    };
    struct xen_domctl domctl =
    {
        .cmd = XEN_DOMCTL_get_vcpu_msrs,
        .domain = ctx->domid,
        .u.vcpu_msrs.vcpu = id,
    };

    if ( xc_domctl(xch, &domctl) < 0 )
    {
        PERROR("Unable to get vcpu%u's msrs", id);
        goto err;
    }

    /* No MSRs? skip this record. */
    if ( !domctl.u.vcpu_msrs.msr_count )
        goto out;

    buffersz = domctl.u.vcpu_msrs.msr_count * sizeof(xen_domctl_vcpu_msr_t);
    buffer = xc_hypercall_buffer_alloc(xch, buffer, buffersz);
    if ( !buffer )
    {
        ERROR("Unable to allocate %zu bytes for vcpu%u's msrs",
              buffersz, id);
        goto err;
    }

    set_xen_guest_handle(domctl.u.vcpu_msrs.msrs, buffer);
    if ( xc_domctl(xch, &domctl) < 0 )
    {
        PERROR("Unable to get vcpu%u's msrs", id);
        goto err;
    }

    /* No MSRs? Skip this record. */
    if ( domctl.u.vcpu_msrs.msr_count == 0 )
        goto out;

    rc = write_split_record(ctx, &rec, buffer,
                            domctl.u.vcpu_msrs.msr_count *
                            sizeof(xen_domctl_vcpu_msr_t));
    if ( rc )
        goto err;

 out:
    rc = 0;

 err:
    xc_hypercall_buffer_free(xch, buffer);

    return rc;
}

/*
 * For each vcpu, if it is online, write its state into the stream.
 */
static int write_all_vcpu_information(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    xc_vcpuinfo_t vinfo;
    unsigned int i;
    int rc;

    for ( i = 0; i <= ctx->dominfo.max_vcpu_id; ++i )
    {
        rc = xc_vcpu_getinfo(xch, ctx->domid, i, &vinfo);
        if ( rc )
        {
            PERROR("Failed to get vcpu%u information", i);
            return rc;
        }

        /* Vcpu offline? skip all these records. */
        if ( !vinfo.online )
            continue;

        rc = write_one_vcpu_basic(ctx, i);
        if ( rc )
            return rc;

        rc = write_one_vcpu_extended(ctx, i);
        if ( rc )
            return rc;

        rc = write_one_vcpu_xsave(ctx, i);
        if ( rc )
            return rc;

        rc = write_one_vcpu_msrs(ctx, i);
        if ( rc )
            return rc;
    }

    return 0;
}

/*
 * Writes an X86_PV_INFO record into the stream.
 */
static int write_x86_pv_info(struct xc_sr_context *ctx)
{
    struct xc_sr_rec_x86_pv_info info =
        {
            .guest_width = ctx->x86_pv.width,
            .pt_levels = ctx->x86_pv.levels,
        };
    struct xc_sr_record rec =
        {
            .type = REC_TYPE_X86_PV_INFO,
            .length = sizeof(info),
            .data = &info
        };

    return write_record(ctx, &rec);
}

/*
 * Writes an X86_PV_P2M_FRAMES record into the stream.  This contains the list
 * of pfns making up the p2m table.
 */
static int write_x86_pv_p2m_frames(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc; unsigned i;
    size_t datasz = ctx->x86_pv.p2m_frames * sizeof(uint64_t);
    uint64_t *data = NULL;
    struct xc_sr_rec_x86_pv_p2m_frames hdr =
        {
            .start_pfn = 0,
            .end_pfn = ctx->x86_pv.max_pfn,
        };
    struct xc_sr_record rec =
        {
            .type = REC_TYPE_X86_PV_P2M_FRAMES,
            .length = sizeof(hdr),
            .data = &hdr,
        };

    /* No need to translate if sizeof(uint64_t) == sizeof(xen_pfn_t). */
    if ( sizeof(uint64_t) != sizeof(*ctx->x86_pv.p2m_pfns) )
    {
        if ( !(data = malloc(datasz)) )
        {
            ERROR("Cannot allocate %zu bytes for X86_PV_P2M_FRAMES data",
                  datasz);
            return -1;
        }

        for ( i = 0; i < ctx->x86_pv.p2m_frames; ++i )
            data[i] = ctx->x86_pv.p2m_pfns[i];
    }
    else
        data = (uint64_t *)ctx->x86_pv.p2m_pfns;

    rc = write_split_record(ctx, &rec, data, datasz);

    if ( data != (uint64_t *)ctx->x86_pv.p2m_pfns )
        free(data);

    return rc;
}

/*
 * Writes an SHARED_INFO record into the stream.
 */
static int write_shared_info(struct xc_sr_context *ctx)
{
    struct xc_sr_record rec =
    {
        .type = REC_TYPE_SHARED_INFO,
        .length = PAGE_SIZE,
        .data = ctx->x86_pv.shinfo,
    };

    return write_record(ctx, &rec);
}

/*
 * Normalise a pagetable for the migration stream.  Performs mfn->pfn
 * conversions on the ptes.
 */
static int normalise_pagetable(struct xc_sr_context *ctx, const uint64_t *src,
                               uint64_t *dst, unsigned long type)
{
    xc_interface *xch = ctx->xch;
    uint64_t pte;
    unsigned i, xen_first = -1, xen_last = -1; /* Indices of Xen mappings. */

    type &= XEN_DOMCTL_PFINFO_LTABTYPE_MASK;

    if ( ctx->x86_pv.levels == 4 )
    {
        /* 64bit guests only have Xen mappings in their L4 tables. */
        if ( type == XEN_DOMCTL_PFINFO_L4TAB )
        {
            xen_first = (HYPERVISOR_VIRT_START_X86_64 >>
                         L4_PAGETABLE_SHIFT_X86_64) & 511;
            xen_last = (HYPERVISOR_VIRT_END_X86_64 >>
                        L4_PAGETABLE_SHIFT_X86_64) & 511;
        }
    }
    else
    {
        switch ( type )
        {
        case XEN_DOMCTL_PFINFO_L4TAB:
            ERROR("??? Found L4 table for 32bit guest");
            errno = EINVAL;
            return -1;

        case XEN_DOMCTL_PFINFO_L3TAB:
            /* 32bit guests can only use the first 4 entries of their L3 tables.
             * All other are potentially used by Xen. */
            xen_first = 4;
            xen_last = 511;
            break;

        case XEN_DOMCTL_PFINFO_L2TAB:
            /* It is hard to spot Xen mappings in a 32bit guest's L2.  Most
             * are normal but only a few will have Xen mappings.
             */
            i = (HYPERVISOR_VIRT_START_X86_32 >> L2_PAGETABLE_SHIFT_PAE) & 511;
            if ( pte_to_frame(src[i]) == ctx->x86_pv.compat_m2p_mfn0 )
            {
                xen_first = i;
                xen_last = (HYPERVISOR_VIRT_END_X86_32 >>
                            L2_PAGETABLE_SHIFT_PAE) & 511;
            }
            break;
        }
    }

    for ( i = 0; i < (PAGE_SIZE / sizeof(uint64_t)); ++i )
    {
        xen_pfn_t mfn;

        pte = src[i];

        /* Remove Xen mappings: Xen will reconstruct on the other side. */
        if ( i >= xen_first && i <= xen_last )
            pte = 0;

        /*
         * Errors during the live part of migration are expected as a result
         * of split pagetable updates, page type changes, active grant
         * mappings etc.  The pagetable will need to be resent after pausing.
         * In such cases we fail with EAGAIN.
         *
         * For domains which are already paused, errors are fatal.
         */
        if ( pte & _PAGE_PRESENT )
        {
            mfn = pte_to_frame(pte);

#ifdef __i386__
            if ( mfn == INVALID_MFN )
            {
                if ( !ctx->dominfo.paused )
                    errno = EAGAIN;
                else
                {
                    ERROR("PTE truncation detected.  L%lu[%u] = %016"PRIx64,
                          type >> XEN_DOMCTL_PFINFO_LTAB_SHIFT, i, pte);
                    errno = E2BIG;
                }
                return -1;
            }
#endif

            if ( (type > XEN_DOMCTL_PFINFO_L1TAB) && (pte & _PAGE_PSE) )
            {
                ERROR("Cannot migrate superpage (L%lu[%u]: 0x%016"PRIx64")",
                      type >> XEN_DOMCTL_PFINFO_LTAB_SHIFT, i, pte);
                errno = E2BIG;
                return -1;
            }

            if ( !mfn_in_pseudophysmap(ctx, mfn) )
            {
                if ( !ctx->dominfo.paused )
                    errno = EAGAIN;
                else
                {
                    ERROR("Bad mfn for L%lu[%u]",
                          type >> XEN_DOMCTL_PFINFO_LTAB_SHIFT, i);
                    dump_bad_pseudophysmap_entry(ctx, mfn);
                    errno = ERANGE;
                }
                return -1;
            }

            pte = merge_pte(pte, mfn_to_pfn(ctx, mfn));
        }

        dst[i] = pte;
    }

    return 0;
}

/* save_ops function. */
static xen_pfn_t x86_pv_pfn_to_gfn(const struct xc_sr_context *ctx,
                                   xen_pfn_t pfn)
{
    assert(pfn <= ctx->x86_pv.max_pfn);

    return xc_pfn_to_mfn(pfn, ctx->x86_pv.p2m, ctx->x86_pv.width);
}


/*
 * save_ops function.  Performs pagetable normalisation on appropriate pages.
 */
static int x86_pv_normalise_page(struct xc_sr_context *ctx, xen_pfn_t type,
                                 void **page)
{
    xc_interface *xch = ctx->xch;
    void *local_page;
    int rc;

    type &= XEN_DOMCTL_PFINFO_LTABTYPE_MASK;

    if ( type < XEN_DOMCTL_PFINFO_L1TAB || type > XEN_DOMCTL_PFINFO_L4TAB )
        return 0;

    local_page = malloc(PAGE_SIZE);
    if ( !local_page )
    {
        ERROR("Unable to allocate scratch page");
        rc = -1;
        goto out;
    }

    rc = normalise_pagetable(ctx, *page, local_page, type);
    *page = local_page;

  out:
    return rc;
}

/*
 * save_ops function.  Queries domain information and maps the Xen m2p and the
 * guests shinfo and p2m table.
 */
static int x86_pv_setup(struct xc_sr_context *ctx)
{
    int rc;

    rc = x86_pv_domain_info(ctx);
    if ( rc )
        return rc;

    rc = x86_pv_map_m2p(ctx);
    if ( rc )
        return rc;

    rc = map_shinfo(ctx);
    if ( rc )
        return rc;

    rc = map_p2m(ctx);
    if ( rc )
        return rc;

    return 0;
}

/*
 * save_ops function.  Writes PV header records into the stream.
 */
static int x86_pv_start_of_stream(struct xc_sr_context *ctx)
{
    int rc;

    rc = write_x86_pv_info(ctx);
    if ( rc )
        return rc;

    /*
     * Ideally should be able to change during migration.  Currently
     * corruption will occur if the contents or location of the P2M changes
     * during the live migration loop.  If one is very lucky, the breakage
     * will not be subtle.
     */
    rc = write_x86_pv_p2m_frames(ctx);
    if ( rc )
        return rc;

    return 0;
}

static int x86_pv_start_of_checkpoint(struct xc_sr_context *ctx)
{
    return 0;
}

static int x86_pv_end_of_checkpoint(struct xc_sr_context *ctx)
{
    int rc;

    rc = write_tsc_info(ctx);
    if ( rc )
        return rc;

    rc = write_shared_info(ctx);
    if ( rc )
        return rc;

    rc = write_all_vcpu_information(ctx);
    if ( rc )
        return rc;

    return 0;
}

static int x86_pv_check_vm_state(struct xc_sr_context *ctx)
{
    if ( ctx->x86_pv.p2m_generation == ~0ULL )
        return 0;

    return x86_pv_check_vm_state_p2m_list(ctx);
}

/*
 * save_ops function.  Cleanup.
 */
static int x86_pv_cleanup(struct xc_sr_context *ctx)
{
    free(ctx->x86_pv.p2m_pfns);

    if ( ctx->x86_pv.p2m )
        munmap(ctx->x86_pv.p2m, ctx->x86_pv.p2m_frames * PAGE_SIZE);

    if ( ctx->x86_pv.shinfo )
        munmap(ctx->x86_pv.shinfo, PAGE_SIZE);

    if ( ctx->x86_pv.m2p )
        munmap(ctx->x86_pv.m2p, ctx->x86_pv.nr_m2p_frames * PAGE_SIZE);

    return 0;
}

struct xc_sr_save_ops save_ops_x86_pv =
{
    .pfn_to_gfn          = x86_pv_pfn_to_gfn,
    .normalise_page      = x86_pv_normalise_page,
    .setup               = x86_pv_setup,
    .start_of_stream     = x86_pv_start_of_stream,
    .start_of_checkpoint = x86_pv_start_of_checkpoint,
    .end_of_checkpoint   = x86_pv_end_of_checkpoint,
    .check_vm_state      = x86_pv_check_vm_state,
    .cleanup             = x86_pv_cleanup,
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
