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
 *
 *  Modified for Xen by:
 *    Wei Liu <wei.liu2@citrix.com>
 */

#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/types.h>

#include <public/sysctl.h>

#include "gcov.h"

/**
 * gcov_store_uint32 - store 32 bit number in gcov format to buffer
 * @buffer: target buffer or NULL
 * @off: offset into the buffer
 * @v: value to be stored
 *
 * Number format defined by gcc: numbers are recorded in the 32 bit
 * unsigned binary form of the endianness of the machine generating the
 * file. Returns the number of bytes stored. If @buffer is %NULL, doesn't
 * store anything.
 */
size_t gcov_store_uint32(void *buffer, size_t off, uint32_t v)
{
    uint32_t *data;

    if ( buffer )
    {
        data = buffer + off;
        *data = v;
    }

    return sizeof(*data);
}

/**
 * gcov_store_uint64 - store 64 bit number in gcov format to buffer
 * @buffer: target buffer or NULL
 * @off: offset into the buffer
 * @v: value to be stored
 *
 * Number format defined by gcc: numbers are recorded in the 32 bit
 * unsigned binary form of the endianness of the machine generating the
 * file. 64 bit numbers are stored as two 32 bit numbers, the low part
 * first. Returns the number of bytes stored. If @buffer is %NULL, doesn't store
 * anything.
 */
size_t gcov_store_uint64(void *buffer, size_t off, uint64_t v)
{
    uint32_t *data;

    if ( buffer )
    {
        data = buffer + off;

        data[0] = (v & 0xffffffffUL);
        data[1] = (v >> 32);
    }

    return sizeof(*data) * 2;
}

static size_t gcov_info_payload_size(const struct gcov_info *info)
{
    return gcov_info_to_gcda(NULL, info);
}

static int gcov_info_dump_payload(const struct gcov_info *info,
                                  XEN_GUEST_HANDLE_PARAM(char) buffer,
                                  uint32_t *off)
{
    char *buf;
    uint32_t buf_size;
    int ret;

    /*
     * Allocate a buffer and dump payload there. This helps us to not
     * have copy_to_guest in other functions and retain their simple
     * semantics.
     */

    buf_size = gcov_info_payload_size(info);
    buf = xmalloc_array(char, buf_size);

    if ( !buf )
    {
        ret = -ENOMEM;
        goto out;
    }

    gcov_info_to_gcda(buf, info);

    if ( copy_to_guest_offset(buffer, *off, buf, buf_size) )
    {
        ret = -EFAULT;
        goto out;
    }
    *off += buf_size;

    ret = 0;
 out:
    xfree(buf);
    return ret;

}

static uint32_t gcov_get_size(void)
{
    uint32_t total_size = sizeof(uint32_t); /* Magic number XCOV */
    struct gcov_info *info = NULL;

    while ( (info = gcov_info_next(info)) )
    {
        /* File name length, including trailing \0 */
        total_size += strlen(gcov_info_filename(info)) + 1;

        /* Payload size field */
        total_size += sizeof(uint32_t);

        /* Payload itself */
        total_size += gcov_info_payload_size(info);
    }

    return total_size;
}

static void gcov_reset_all_counters(void)
{
    struct gcov_info *info = NULL;

    while ( (info = gcov_info_next(info)) )
        gcov_info_reset(info);
}

static int gcov_dump_one_record(const struct gcov_info *info,
                                XEN_GUEST_HANDLE_PARAM(char) buffer,
                                uint32_t *off)
{
    uint32_t payload_size;
    uint32_t len;

    /* File name, including trailing \0 */
    len = strlen(gcov_info_filename(info)) + 1;
    if ( copy_to_guest_offset(buffer, *off, gcov_info_filename(info), len) )
        return -EFAULT;
    *off += len;

    payload_size = gcov_info_payload_size(info);
    /* Payload size */
    if ( copy_to_guest_offset(buffer, *off, (char*)&payload_size,
                              sizeof(uint32_t)) )
        return -EFAULT;
    *off += sizeof(uint32_t);

    /* Payload itself */
    return gcov_info_dump_payload(info, buffer, off);
}

static int gcov_dump_all(XEN_GUEST_HANDLE_PARAM(char) buffer,
                         uint32_t *buffer_size)
{
    uint32_t off;
    uint32_t magic = XEN_GCOV_FORMAT_MAGIC;
    struct gcov_info *info = NULL;
    int ret;

    if ( *buffer_size < gcov_get_size() )
    {
        ret = -ENOBUFS;
        goto out;
    }

    off = 0;

    /* Magic number */
    if ( copy_to_guest_offset(buffer, off, (char *)&magic, sizeof(magic)) )
    {
        ret = -EFAULT;
        goto out;
    }
    off += sizeof(magic);

    while ( (info = gcov_info_next(info)) )
    {
        ret = gcov_dump_one_record(info, buffer, &off);
        if ( ret )
            goto out;
    }

    *buffer_size = off;

    ret = 0;
 out:
    return ret;
}

int sysctl_gcov_op(struct xen_sysctl_gcov_op *op)
{
    int ret;

    switch ( op->cmd )
    {
    case XEN_SYSCTL_GCOV_get_size:
        op->size = gcov_get_size();
        ret = 0;
        break;

    case XEN_SYSCTL_GCOV_read:
    {
        XEN_GUEST_HANDLE_PARAM(char) buf;
        uint32_t size = op->size;

        buf = guest_handle_cast(op->buffer, char);

        ret = gcov_dump_all(buf, &size);
        op->size = size;

        break;
    }

    case XEN_SYSCTL_GCOV_reset:
        gcov_reset_all_counters();
        ret = 0;
        break;

    default:
        ret = -EOPNOTSUPP;
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
