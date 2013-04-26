/*
 *  This code maintains a list of active profiling data structures.
 *
 *    Copyright IBM Corp. 2009
 *    Author(s): Peter Oberparleiter <oberpar@linux.vnet.ibm.com>
 *
 *    Uses gcc-internal data definitions.
 *    Based on the gcov-kernel patch by:
 *       Hubertus Franke <frankeh@us.ibm.com>
 *       Nigel Hinds <nhinds@us.ibm.com>
 *       Rajan Ravindran <rajancr@us.ibm.com>
 *       Peter Oberparleiter <oberpar@linux.vnet.ibm.com>
 *       Paul Larson
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/hypercall.h>
#include <xen/gcov.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <public/xen.h>
#include <public/gcov.h>

static struct gcov_info *info_list;

/*
 * __gcov_init is called by gcc-generated constructor code for each object
 * file compiled with -fprofile-arcs.
 *
 * Although this function is called only during initialization is called from
 * a .text section which is still present after initialization so not declare
 * as __init.
 */
void __gcov_init(struct gcov_info *info)
{
    /* add new profiling data structure to list */
    info->next = info_list;
    info_list = info;
}

/*
 * These functions may be referenced by gcc-generated profiling code but serve
 * no function for Xen.
 */
void __gcov_flush(void)
{
    /* Unused. */
}

void __gcov_merge_add(gcov_type *counters, unsigned int n_counters)
{
    /* Unused. */
}

void __gcov_merge_single(gcov_type *counters, unsigned int n_counters)
{
    /* Unused. */
}

void __gcov_merge_delta(gcov_type *counters, unsigned int n_counters)
{
    /* Unused. */
}

static inline int counter_active(const struct gcov_info *info, unsigned int type)
{
    return (1 << type) & info->ctr_mask;
}

typedef struct write_iter_t
{
    XEN_GUEST_HANDLE(uint8) ptr;
    int real;
    uint32_t write_offset;
} write_iter_t;

static int write_raw(struct write_iter_t *iter, const void *data,
                     size_t data_len)
{
    if ( iter->real &&
        copy_to_guest_offset(iter->ptr, iter->write_offset,
                             (const unsigned char *) data, data_len) )
        return -EFAULT;

    iter->write_offset += data_len;
    return 0;
}

#define chk(v) do { ret=(v); if ( ret ) return ret; } while(0)

static inline int write32(write_iter_t *iter, uint32_t val)
{
    return write_raw(iter, &val, sizeof(val));
}

static int write_string(write_iter_t *iter, const char *s)
{
    int ret;
    size_t len = strlen(s);

    chk(write32(iter, len));
    return write_raw(iter, s, len);
}

static inline int next_type(const struct gcov_info *info, int *type)
{
    while ( ++*type < XENCOV_COUNTERS && !counter_active(info, *type) )
        continue;
    return *type;
}

static inline void align_iter(write_iter_t *iter)
{
    iter->write_offset =
        (iter->write_offset + sizeof(uint64_t) - 1) & -sizeof(uint64_t);
}

static int write_gcov(write_iter_t *iter)
{
    struct gcov_info *info;
    int ret;

    /* reset offset */
    iter->write_offset = 0;

    /* dump all files */
    for ( info = info_list ; info; info = info->next )
    {
        const struct gcov_ctr_info *ctr;
        int type;
        size_t size_fn = sizeof(struct gcov_fn_info);

        align_iter(iter);
        chk(write32(iter, XENCOV_TAG_FILE));
        chk(write32(iter, info->version));
        chk(write32(iter, info->stamp));
        chk(write_string(iter, info->filename));

        /* dump counters */
        ctr = info->counts;
        for ( type = -1; next_type(info, &type) < XENCOV_COUNTERS; ++ctr )
        {
            align_iter(iter);
            chk(write32(iter, XENCOV_TAG_COUNTER(type)));
            chk(write32(iter, ctr->num));
            chk(write_raw(iter, ctr->values,
                          ctr->num * sizeof(ctr->values[0])));

            size_fn += sizeof(unsigned);
        }

        /* dump all functions together */
        align_iter(iter);
        chk(write32(iter, XENCOV_TAG_FUNC));
        chk(write32(iter, info->n_functions));
        chk(write_raw(iter, info->functions, info->n_functions * size_fn));
    }

    /* stop tag */
    align_iter(iter);
    chk(write32(iter, XENCOV_TAG_END));
    return 0;
}

static int reset_counters(void)
{
    struct gcov_info *info;

    for ( info = info_list ; info; info = info->next )
    {
        const struct gcov_ctr_info *ctr;
        int type;

        /* reset counters */
        ctr = info->counts;
        for ( type = -1; next_type(info, &type) < XENCOV_COUNTERS; ++ctr )
            memset(ctr->values, 0, ctr->num * sizeof(ctr->values[0]));
    }

    return 0;
}

int sysctl_coverage_op(xen_sysctl_coverage_op_t *op)
{
    int ret = -EINVAL;
    write_iter_t iter;

    switch ( op->cmd )
    {
    case XEN_SYSCTL_COVERAGE_get_total_size:
        iter.real = 0;

        write_gcov(&iter);
        op->u.total_size = iter.write_offset;
        ret = 0;
        break;

    case XEN_SYSCTL_COVERAGE_read_and_reset:
    case XEN_SYSCTL_COVERAGE_read:
        iter.ptr = op->u.raw_info;
        iter.real = 1;

        ret = write_gcov(&iter);
        if ( ret || op->cmd != XEN_SYSCTL_COVERAGE_read_and_reset )
            break;

        /* fall through */
    case XEN_SYSCTL_COVERAGE_reset:
        ret = reset_counters();
        break;
    }
    return ret;
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
