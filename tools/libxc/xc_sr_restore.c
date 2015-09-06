#include <arpa/inet.h>

#include <assert.h>

#include "xc_sr_common.h"

/*
 * Read and validate the Image and Domain headers.
 */
static int read_headers(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_ihdr ihdr;
    struct xc_sr_dhdr dhdr;

    if ( read_exact(ctx->fd, &ihdr, sizeof(ihdr)) )
    {
        PERROR("Failed to read Image Header from stream");
        return -1;
    }

    ihdr.id      = ntohl(ihdr.id);
    ihdr.version = ntohl(ihdr.version);
    ihdr.options = ntohs(ihdr.options);

    if ( ihdr.marker != IHDR_MARKER )
    {
        ERROR("Invalid marker: Got 0x%016"PRIx64, ihdr.marker);
        return -1;
    }
    else if ( ihdr.id != IHDR_ID )
    {
        ERROR("Invalid ID: Expected 0x%08x, Got 0x%08x", IHDR_ID, ihdr.id);
        return -1;
    }
    else if ( ihdr.version != IHDR_VERSION )
    {
        ERROR("Invalid Version: Expected %d, Got %d",
              ihdr.version, IHDR_VERSION);
        return -1;
    }
    else if ( ihdr.options & IHDR_OPT_BIG_ENDIAN )
    {
        ERROR("Unable to handle big endian streams");
        return -1;
    }

    ctx->restore.format_version = ihdr.version;

    if ( read_exact(ctx->fd, &dhdr, sizeof(dhdr)) )
    {
        PERROR("Failed to read Domain Header from stream");
        return -1;
    }

    ctx->restore.guest_type = dhdr.type;
    ctx->restore.guest_page_size = (1U << dhdr.page_shift);

    if ( dhdr.xen_major == 0 )
    {
        IPRINTF("Found %s domain, converted from legacy stream format",
                dhdr_type_to_str(dhdr.type));
        DPRINTF("  Legacy conversion script version %u", dhdr.xen_minor);
    }
    else
        IPRINTF("Found %s domain from Xen %u.%u",
                dhdr_type_to_str(dhdr.type), dhdr.xen_major, dhdr.xen_minor);
    return 0;
}

/*
 * Reads a record from the stream, and fills in the record structure.
 *
 * Returns 0 on success and non-0 on failure.
 *
 * On success, the records type and size shall be valid.
 * - If size is 0, data shall be NULL.
 * - If size is non-0, data shall be a buffer allocated by malloc() which must
 *   be passed to free() by the caller.
 *
 * On failure, the contents of the record structure are undefined.
 */
static int read_record(struct xc_sr_context *ctx, struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rhdr rhdr;
    size_t datasz;

    if ( read_exact(ctx->fd, &rhdr, sizeof(rhdr)) )
    {
        PERROR("Failed to read Record Header from stream");
        return -1;
    }
    else if ( rhdr.length > REC_LENGTH_MAX )
    {
        ERROR("Record (0x%08x, %s) length %#x exceeds max (%#x)", rhdr.type,
              rec_type_to_str(rhdr.type), rhdr.length, REC_LENGTH_MAX);
        return -1;
    }

    datasz = ROUNDUP(rhdr.length, REC_ALIGN_ORDER);

    if ( datasz )
    {
        rec->data = malloc(datasz);

        if ( !rec->data )
        {
            ERROR("Unable to allocate %zu bytes for record data (0x%08x, %s)",
                  datasz, rhdr.type, rec_type_to_str(rhdr.type));
            return -1;
        }

        if ( read_exact(ctx->fd, rec->data, datasz) )
        {
            free(rec->data);
            rec->data = NULL;
            PERROR("Failed to read %zu bytes of data for record (0x%08x, %s)",
                   datasz, rhdr.type, rec_type_to_str(rhdr.type));
            return -1;
        }
    }
    else
        rec->data = NULL;

    rec->type   = rhdr.type;
    rec->length = rhdr.length;

    return 0;
};

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
 * avoid realloc()ing too excessively, the size increased to the nearest power
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

    assert(!test_bit(pfn, ctx->restore.populated_pfns));
    set_bit(pfn, ctx->restore.populated_pfns);

    return 0;
}

/*
 * Given a set of pfns, obtain memory from Xen to fill the physmap for the
 * unpopulated subset.  If types is NULL, no page type checking is performed
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
            rc = pfn_set_populated(ctx, original_pfns[i]);
            if ( rc )
                goto err;
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

            ctx->restore.ops.set_gfn(ctx, pfns[i], mfns[i]);
        }
    }

    rc = 0;

 err:
    free(pfns);
    free(mfns);

    return rc;
}

/*
 * Given a list of pfns, their types, and a block of page data from the
 * stream, populate and record their types, map the relevant subset and copy
 * the data into the guest.
 */
static int process_page_data(struct xc_sr_context *ctx, unsigned count,
                             xen_pfn_t *pfns, uint32_t *types, void *page_data)
{
    xc_interface *xch = ctx->xch;
    xen_pfn_t *mfns = malloc(count * sizeof(*mfns));
    int *map_errs = malloc(count * sizeof(*map_errs));
    int rc;
    void *mapping = NULL, *guest_page = NULL;
    unsigned i,    /* i indexes the pfns from the record. */
        j,         /* j indexes the subset of pfns we decide to map. */
        nr_pages = 0;

    if ( !mfns || !map_errs )
    {
        rc = -1;
        ERROR("Failed to allocate %zu bytes to process page data",
              count * (sizeof(*mfns) + sizeof(*map_errs)));
        goto err;
    }

    rc = populate_pfns(ctx, count, pfns, types);
    if ( rc )
    {
        ERROR("Failed to populate pfns for batch of %u pages", count);
        goto err;
    }

    for ( i = 0; i < count; ++i )
    {
        ctx->restore.ops.set_page_type(ctx, pfns[i], types[i]);

        switch ( types[i] )
        {
        case XEN_DOMCTL_PFINFO_NOTAB:

        case XEN_DOMCTL_PFINFO_L1TAB:
        case XEN_DOMCTL_PFINFO_L1TAB | XEN_DOMCTL_PFINFO_LPINTAB:

        case XEN_DOMCTL_PFINFO_L2TAB:
        case XEN_DOMCTL_PFINFO_L2TAB | XEN_DOMCTL_PFINFO_LPINTAB:

        case XEN_DOMCTL_PFINFO_L3TAB:
        case XEN_DOMCTL_PFINFO_L3TAB | XEN_DOMCTL_PFINFO_LPINTAB:

        case XEN_DOMCTL_PFINFO_L4TAB:
        case XEN_DOMCTL_PFINFO_L4TAB | XEN_DOMCTL_PFINFO_LPINTAB:

            mfns[nr_pages++] = ctx->restore.ops.pfn_to_gfn(ctx, pfns[i]);
            break;
        }
    }

    /* Nothing to do? */
    if ( nr_pages == 0 )
        goto done;

    mapping = guest_page = xc_map_foreign_bulk(
        xch, ctx->domid, PROT_READ | PROT_WRITE,
        mfns, map_errs, nr_pages);
    if ( !mapping )
    {
        rc = -1;
        PERROR("Unable to map %u mfns for %u pages of data",
               nr_pages, count);
        goto err;
    }

    for ( i = 0, j = 0; i < count; ++i )
    {
        switch ( types[i] )
        {
        case XEN_DOMCTL_PFINFO_XTAB:
        case XEN_DOMCTL_PFINFO_BROKEN:
        case XEN_DOMCTL_PFINFO_XALLOC:
            /* No page data to deal with. */
            continue;
        }

        if ( map_errs[j] )
        {
            rc = -1;
            ERROR("Mapping pfn %lx (mfn %lx, type %#x)failed with %d",
                  pfns[i], mfns[j], types[i], map_errs[j]);
            goto err;
        }

        /* Undo page normalisation done by the saver. */
        rc = ctx->restore.ops.localise_page(ctx, types[i], page_data);
        if ( rc )
        {
            ERROR("Failed to localise pfn %lx (type %#x)",
                  pfns[i], types[i] >> XEN_DOMCTL_PFINFO_LTAB_SHIFT);
            goto err;
        }

        if ( ctx->restore.verify )
        {
            /* Verify mode - compare incoming data to what we already have. */
            if ( memcmp(guest_page, page_data, PAGE_SIZE) )
                ERROR("verify pfn %lx failed (type %#x)",
                      pfns[i], types[i] >> XEN_DOMCTL_PFINFO_LTAB_SHIFT);
        }
        else
        {
            /* Regular mode - copy incoming data into place. */
            memcpy(guest_page, page_data, PAGE_SIZE);
        }

        ++j;
        guest_page += PAGE_SIZE;
        page_data += PAGE_SIZE;
    }

 done:
    rc = 0;

 err:
    if ( mapping )
        munmap(mapping, nr_pages * PAGE_SIZE);

    free(map_errs);
    free(mfns);

    return rc;
}

/*
 * Validate a PAGE_DATA record from the stream, and pass the results to
 * process_page_data() to actually perform the legwork.
 */
static int handle_page_data(struct xc_sr_context *ctx, struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_page_data_header *pages = rec->data;
    unsigned i, pages_of_data = 0;
    int rc = -1;

    xen_pfn_t *pfns = NULL, pfn;
    uint32_t *types = NULL, type;

    if ( rec->length < sizeof(*pages) )
    {
        ERROR("PAGE_DATA record truncated: length %u, min %zu",
              rec->length, sizeof(*pages));
        goto err;
    }
    else if ( pages->count < 1 )
    {
        ERROR("Expected at least 1 pfn in PAGE_DATA record");
        goto err;
    }
    else if ( rec->length < sizeof(*pages) + (pages->count * sizeof(uint64_t)) )
    {
        ERROR("PAGE_DATA record (length %u) too short to contain %u"
              " pfns worth of information", rec->length, pages->count);
        goto err;
    }

    pfns = malloc(pages->count * sizeof(*pfns));
    types = malloc(pages->count * sizeof(*types));
    if ( !pfns || !types )
    {
        ERROR("Unable to allocate enough memory for %u pfns",
              pages->count);
        goto err;
    }

    for ( i = 0; i < pages->count; ++i )
    {
        pfn = pages->pfn[i] & PAGE_DATA_PFN_MASK;
        if ( !ctx->restore.ops.pfn_is_valid(ctx, pfn) )
        {
            ERROR("pfn %#lx (index %u) outside domain maximum", pfn, i);
            goto err;
        }

        type = (pages->pfn[i] & PAGE_DATA_TYPE_MASK) >> 32;
        if ( ((type >> XEN_DOMCTL_PFINFO_LTAB_SHIFT) >= 5) &&
             ((type >> XEN_DOMCTL_PFINFO_LTAB_SHIFT) <= 8) )
        {
            ERROR("Invalid type %#x for pfn %#lx (index %u)", type, pfn, i);
            goto err;
        }
        else if ( type < XEN_DOMCTL_PFINFO_BROKEN )
            /* NOTAB and all L1 through L4 tables (including pinned) should
             * have a page worth of data in the record. */
            pages_of_data++;

        pfns[i] = pfn;
        types[i] = type;
    }

    if ( rec->length != (sizeof(*pages) +
                         (sizeof(uint64_t) * pages->count) +
                         (PAGE_SIZE * pages_of_data)) )
    {
        ERROR("PAGE_DATA record wrong size: length %u, expected "
              "%zu + %zu + %lu", rec->length, sizeof(*pages),
              (sizeof(uint64_t) * pages->count), (PAGE_SIZE * pages_of_data));
        goto err;
    }

    rc = process_page_data(ctx, pages->count, pfns, types,
                           &pages->pfn[pages->count]);
 err:
    free(types);
    free(pfns);

    return rc;
}

static int process_record(struct xc_sr_context *ctx, struct xc_sr_record *rec);
static int handle_checkpoint(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc = 0, ret;
    unsigned i;

    if ( !ctx->restore.checkpointed )
    {
        ERROR("Found checkpoint in non-checkpointed stream");
        rc = -1;
        goto err;
    }

    ret = ctx->restore.callbacks->checkpoint(ctx->restore.callbacks->data);
    switch ( ret )
    {
    case XGR_CHECKPOINT_SUCCESS:
        break;

    case XGR_CHECKPOINT_FAILOVER:
        rc = BROKEN_CHANNEL;
        goto err;

    default: /* Other fatal error */
        rc = -1;
        goto err;
    }

    if ( ctx->restore.buffer_all_records )
    {
        IPRINTF("All records buffered");

        for ( i = 0; i < ctx->restore.buffered_rec_num; i++ )
        {
            rc = process_record(ctx, &ctx->restore.buffered_records[i]);
            if ( rc )
                goto err;
        }
        ctx->restore.buffered_rec_num = 0;
        IPRINTF("All records processed");
    }
    else
        ctx->restore.buffer_all_records = true;

 err:
    return rc;
}

static int buffer_record(struct xc_sr_context *ctx, struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    unsigned new_alloc_num;
    struct xc_sr_record *p;

    if ( ctx->restore.buffered_rec_num >= ctx->restore.allocated_rec_num )
    {
        new_alloc_num = ctx->restore.allocated_rec_num + DEFAULT_BUF_RECORDS;
        p = realloc(ctx->restore.buffered_records,
                    new_alloc_num * sizeof(struct xc_sr_record));
        if ( !p )
        {
            ERROR("Failed to realloc memory for buffered records");
            return -1;
        }

        ctx->restore.buffered_records = p;
        ctx->restore.allocated_rec_num = new_alloc_num;
    }

    memcpy(&ctx->restore.buffered_records[ctx->restore.buffered_rec_num++],
           rec, sizeof(*rec));

    return 0;
}

static int process_record(struct xc_sr_context *ctx, struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    int rc = 0;

    switch ( rec->type )
    {
    case REC_TYPE_END:
        break;

    case REC_TYPE_PAGE_DATA:
        rc = handle_page_data(ctx, rec);
        break;

    case REC_TYPE_VERIFY:
        DPRINTF("Verify mode enabled");
        ctx->restore.verify = true;
        break;

    case REC_TYPE_CHECKPOINT:
        rc = handle_checkpoint(ctx);
        break;

    default:
        rc = ctx->restore.ops.process_record(ctx, rec);
        break;
    }

    free(rec->data);
    rec->data = NULL;

    return rc;
}

static int setup(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc;

    rc = ctx->restore.ops.setup(ctx);
    if ( rc )
        goto err;

    ctx->restore.max_populated_pfn = (32 * 1024 / 4) - 1;
    ctx->restore.populated_pfns = bitmap_alloc(
        ctx->restore.max_populated_pfn + 1);
    if ( !ctx->restore.populated_pfns )
    {
        ERROR("Unable to allocate memory for populated_pfns bitmap");
        rc = -1;
        goto err;
    }

    ctx->restore.buffered_records = malloc(
        DEFAULT_BUF_RECORDS * sizeof(struct xc_sr_record));
    if ( !ctx->restore.buffered_records )
    {
        ERROR("Unable to allocate memory for buffered records");
        rc = -1;
        goto err;
    }
    ctx->restore.allocated_rec_num = DEFAULT_BUF_RECORDS;

 err:
    return rc;
}

static void cleanup(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    unsigned i;

    for ( i = 0; i < ctx->restore.buffered_rec_num; i++ )
        free(ctx->restore.buffered_records[i].data);

    free(ctx->restore.buffered_records);
    free(ctx->restore.populated_pfns);
    if ( ctx->restore.ops.cleanup(ctx) )
        PERROR("Failed to clean up");
}

/*
 * Restore a domain.
 */
static int restore(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_record rec;
    int rc, saved_rc = 0, saved_errno = 0;

    IPRINTF("Restoring domain");

    rc = setup(ctx);
    if ( rc )
        goto err;

    do
    {
        rc = read_record(ctx, &rec);
        if ( rc )
        {
            if ( ctx->restore.buffer_all_records )
                goto remus_failover;
            else
                goto err;
        }

        if ( ctx->restore.buffer_all_records &&
             rec.type != REC_TYPE_END &&
             rec.type != REC_TYPE_CHECKPOINT )
        {
            rc = buffer_record(ctx, &rec);
            if ( rc )
                goto err;
        }
        else
        {
            rc = process_record(ctx, &rec);
            if ( rc == RECORD_NOT_PROCESSED )
            {
                if ( rec.type & REC_TYPE_OPTIONAL )
                    DPRINTF("Ignoring optional record %#x (%s)",
                            rec.type, rec_type_to_str(rec.type));
                else
                {
                    ERROR("Mandatory record %#x (%s) not handled",
                          rec.type, rec_type_to_str(rec.type));
                    rc = -1;
                    goto err;
                }
            }
            else if ( rc == BROKEN_CHANNEL )
                goto remus_failover;
            else if ( rc )
                goto err;
        }

    } while ( rec.type != REC_TYPE_END );

 remus_failover:
    /*
     * With Remus, if we reach here, there must be some error on primary,
     * failover from the last checkpoint state.
     */
    rc = ctx->restore.ops.stream_complete(ctx);
    if ( rc )
        goto err;

    IPRINTF("Restore successful");
    goto done;

 err:
    saved_errno = errno;
    saved_rc = rc;
    PERROR("Restore failed");

 done:
    cleanup(ctx);

    if ( saved_rc )
    {
        rc = saved_rc;
        errno = saved_errno;
    }

    return rc;
}

int xc_domain_restore(xc_interface *xch, int io_fd, uint32_t dom,
                      unsigned int store_evtchn, unsigned long *store_mfn,
                      domid_t store_domid, unsigned int console_evtchn,
                      unsigned long *console_gfn, domid_t console_domid,
                      unsigned int hvm, unsigned int pae, int superpages,
                      int checkpointed_stream,
                      struct restore_callbacks *callbacks)
{
    struct xc_sr_context ctx =
        {
            .xch = xch,
            .fd = io_fd,
        };

    /* GCC 4.4 (of CentOS 6.x vintage) can' t initialise anonymous unions. */
    ctx.restore.console_evtchn = console_evtchn;
    ctx.restore.console_domid = console_domid;
    ctx.restore.xenstore_evtchn = store_evtchn;
    ctx.restore.xenstore_domid = store_domid;
    ctx.restore.checkpointed = checkpointed_stream;
    ctx.restore.callbacks = callbacks;

    /* Sanity checks for callbacks. */
    if ( checkpointed_stream )
        assert(callbacks->checkpoint);

    DPRINTF("fd %d, dom %u, hvm %u, pae %u, superpages %d"
            ", checkpointed_stream %d", io_fd, dom, hvm, pae,
            superpages, checkpointed_stream);

    if ( xc_domain_getinfo(xch, dom, 1, &ctx.dominfo) != 1 )
    {
        PERROR("Failed to get domain info");
        return -1;
    }

    if ( ctx.dominfo.domid != dom )
    {
        ERROR("Domain %u does not exist", dom);
        return -1;
    }

    ctx.domid = dom;

    if ( read_headers(&ctx) )
        return -1;

    if ( ctx.dominfo.hvm )
    {
        ctx.restore.ops = restore_ops_x86_hvm;
        if ( restore(&ctx) )
            return -1;
    }
    else
    {
        ctx.restore.ops = restore_ops_x86_pv;
        if ( restore(&ctx) )
            return -1;
    }

    IPRINTF("XenStore: mfn %#lx, dom %d, evt %u",
            ctx.restore.xenstore_gfn,
            ctx.restore.xenstore_domid,
            ctx.restore.xenstore_evtchn);

    IPRINTF("Console: mfn %#lx, dom %d, evt %u",
            ctx.restore.console_gfn,
            ctx.restore.console_domid,
            ctx.restore.console_evtchn);

    *console_gfn = ctx.restore.console_gfn;
    *store_mfn = ctx.restore.xenstore_gfn;

    return 0;
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
