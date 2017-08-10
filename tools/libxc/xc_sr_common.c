#include <assert.h>

#include "xc_sr_common.h"

#include <xen-tools/libs.h>

static const char *dhdr_types[] =
{
    [DHDR_TYPE_X86_PV]  = "x86 PV",
    [DHDR_TYPE_X86_HVM] = "x86 HVM",
    [DHDR_TYPE_X86_PVH] = "x86 PVH",
    [DHDR_TYPE_ARM]     = "ARM",
};

const char *dhdr_type_to_str(uint32_t type)
{
    if ( type < ARRAY_SIZE(dhdr_types) && dhdr_types[type] )
        return dhdr_types[type];

    return "Reserved";
}

static const char *mandatory_rec_types[] =
{
    [REC_TYPE_END]                          = "End",
    [REC_TYPE_PAGE_DATA]                    = "Page data",
    [REC_TYPE_X86_PV_INFO]                  = "x86 PV info",
    [REC_TYPE_X86_PV_P2M_FRAMES]            = "x86 PV P2M frames",
    [REC_TYPE_X86_PV_VCPU_BASIC]            = "x86 PV vcpu basic",
    [REC_TYPE_X86_PV_VCPU_EXTENDED]         = "x86 PV vcpu extended",
    [REC_TYPE_X86_PV_VCPU_XSAVE]            = "x86 PV vcpu xsave",
    [REC_TYPE_SHARED_INFO]                  = "Shared info",
    [REC_TYPE_TSC_INFO]                     = "TSC info",
    [REC_TYPE_HVM_CONTEXT]                  = "HVM context",
    [REC_TYPE_HVM_PARAMS]                   = "HVM params",
    [REC_TYPE_TOOLSTACK]                    = "Toolstack",
    [REC_TYPE_X86_PV_VCPU_MSRS]             = "x86 PV vcpu msrs",
    [REC_TYPE_VERIFY]                       = "Verify",
    [REC_TYPE_CHECKPOINT]                   = "Checkpoint",
    [REC_TYPE_CHECKPOINT_DIRTY_PFN_LIST]    = "Checkpoint dirty pfn list",
};

const char *rec_type_to_str(uint32_t type)
{
    if ( !(type & REC_TYPE_OPTIONAL) )
    {
        if ( (type < ARRAY_SIZE(mandatory_rec_types)) &&
             (mandatory_rec_types[type]) )
            return mandatory_rec_types[type];
    }

    return "Reserved";
}

int write_split_record(struct xc_sr_context *ctx, struct xc_sr_record *rec,
                       void *buf, size_t sz)
{
    static const char zeroes[(1u << REC_ALIGN_ORDER) - 1] = { 0 };

    xc_interface *xch = ctx->xch;
    typeof(rec->length) combined_length = rec->length + sz;
    size_t record_length = ROUNDUP(combined_length, REC_ALIGN_ORDER);
    struct iovec parts[] =
    {
        { &rec->type,       sizeof(rec->type) },
        { &combined_length, sizeof(combined_length) },
        { rec->data,        rec->length },
        { buf,              sz },
        { (void*)zeroes,    record_length - combined_length },
    };

    if ( record_length > REC_LENGTH_MAX )
    {
        ERROR("Record (0x%08x, %s) length %#zx exceeds max (%#x)", rec->type,
              rec_type_to_str(rec->type), record_length, REC_LENGTH_MAX);
        return -1;
    }

    if ( rec->length )
        assert(rec->data);
    if ( sz )
        assert(buf);

    if ( writev_exact(ctx->fd, parts, ARRAY_SIZE(parts)) )
        goto err;

    return 0;

 err:
    PERROR("Unable to write record to stream");
    return -1;
}

int read_record(struct xc_sr_context *ctx, int fd, struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rhdr rhdr;
    size_t datasz;

    if ( read_exact(fd, &rhdr, sizeof(rhdr)) )
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

        if ( read_exact(fd, rec->data, datasz) )
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

static void __attribute__((unused)) build_assertions(void)
{
    BUILD_BUG_ON(sizeof(struct xc_sr_ihdr) != 24);
    BUILD_BUG_ON(sizeof(struct xc_sr_dhdr) != 16);
    BUILD_BUG_ON(sizeof(struct xc_sr_rhdr) != 8);

    BUILD_BUG_ON(sizeof(struct xc_sr_rec_page_data_header)  != 8);
    BUILD_BUG_ON(sizeof(struct xc_sr_rec_x86_pv_info)       != 8);
    BUILD_BUG_ON(sizeof(struct xc_sr_rec_x86_pv_p2m_frames) != 8);
    BUILD_BUG_ON(sizeof(struct xc_sr_rec_x86_pv_vcpu_hdr)   != 8);
    BUILD_BUG_ON(sizeof(struct xc_sr_rec_tsc_info)          != 24);
    BUILD_BUG_ON(sizeof(struct xc_sr_rec_hvm_params_entry)  != 16);
    BUILD_BUG_ON(sizeof(struct xc_sr_rec_hvm_params)        != 8);
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
