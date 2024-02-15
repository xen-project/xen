/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * xen-9pfsd - Xen 9pfs daemon
 *
 * Copyright (C) 2024 Juergen Gross <jgross@suse.com>
 *
 * I/O thread handling.
 *
 * Only handle one request at a time, pushing out the complete response
 * before looking for the next request.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <xenctrl.h>           /* For cpu barriers. */
#include <xen-tools/common-macros.h>

#include "xen-9pfsd.h"

/* P9 protocol commands (response is either cmd+1 or P9_CMD_ERROR). */
#define P9_CMD_VERSION    100
#define P9_CMD_ERROR      107

#define P9_MIN_MSIZE      2048
#define P9_VERSION        "9P2000.u"

struct p9_qid {
    uint8_t type;
#define QID_TYPE_DIR      0x80
    uint32_t version;
    uint64_t path;
};

/*
 * Note that the ring names "in" and "out" are from the frontend's
 * perspective, so the "in" ring will be used for responses to the frontend,
 * while the "out" ring is used for requests from the frontend to the
 * backend.
 */
static unsigned int ring_in_free(struct ring *ring)
{
    unsigned int queued;

    queued = xen_9pfs_queued(ring->prod_pvt_in, ring->intf->in_cons,
                             ring->ring_size);
    xen_rmb();

    return ring->ring_size - queued;
}

static unsigned int ring_out_data(struct ring *ring)
{
    unsigned int queued;

    queued = xen_9pfs_queued(ring->intf->out_prod, ring->cons_pvt_out,
                             ring->ring_size);
    xen_rmb();

    return queued;
}

static unsigned int get_request_bytes(struct ring *ring, unsigned int off,
                                      unsigned int total_len)
{
    unsigned int size;
    unsigned int out_data = ring_out_data(ring);
    RING_IDX prod, cons;

    size = min(total_len - off, out_data);
    prod = xen_9pfs_mask(ring->intf->out_prod, ring->ring_size);
    cons = xen_9pfs_mask(ring->cons_pvt_out, ring->ring_size);
    xen_9pfs_read_packet(ring->buffer + off, ring->data.out, size,
                         prod, &cons, ring->ring_size);

    xen_rmb();           /* Read data out before setting visible consumer. */
    ring->cons_pvt_out += size;
    ring->intf->out_cons = ring->cons_pvt_out;

    /* Signal that more space is available now. */
    xenevtchn_notify(xe, ring->evtchn);

    return size;
}

static unsigned int put_response_bytes(struct ring *ring, unsigned int off,
                                       unsigned int total_len)
{
    unsigned int size;
    unsigned int in_data = ring_in_free(ring);
    RING_IDX prod, cons;

    size = min(total_len - off, in_data);
    prod = xen_9pfs_mask(ring->prod_pvt_in, ring->ring_size);
    cons = xen_9pfs_mask(ring->intf->in_cons, ring->ring_size);
    xen_9pfs_write_packet(ring->data.in, ring->buffer + off, size,
                          &prod, cons, ring->ring_size);

    xen_wmb();           /* Write data out before setting visible producer. */
    ring->prod_pvt_in += size;
    ring->intf->in_prod = ring->prod_pvt_in;

    return size;
}

static bool io_work_pending(struct ring *ring)
{
    if ( ring->stop_thread )
        return true;
    if ( ring->error )
        return false;
    return ring->handle_response ? ring_in_free(ring) : ring_out_data(ring);
}

static void fmt_err(const char *fmt)
{
    syslog(LOG_CRIT, "illegal format %s passed to fill_buffer()", fmt);
    exit(1);
}

/*
 * Fill buffer with response data.
 * fmt is a sequence of format characters. Supported characters are:
 * a: an array (2 bytes number of elements + the following format as elements)
 *    The number of elements is passed in the first unsigned int parameter, the
 *    next parameter is a pointer to an array of elements as denoted by the next
 *    format character.
 * b: 1 byte unsigned integer
 * u: 2 byte unsigned integer
 *    The parameter is a pointer to a uint16_t value
 * D: Data blob (4 byte length + <length> bytes)
 *    2 parameters are consumed, first an unsigned int for the length, then a
 *    pointer to the first uint8_t value.
 *    No array support.
 * L: 8 byte unsigned integer
 *    The parameter is a pointer to a uint64_t value
 * Q: Qid (struct p9_qid)
 * S: String (2 byte length + <length> characters)
 *    The length is obtained via strlen() of the parameter, being a pointer
 *    to the first character of the string
 * U: 4 byte unsigned integer
 *    The parameter is a pointer to a uint32_t value
 */
static void fill_buffer_at(void **data, const char *fmt, ...);
static void vfill_buffer_at(void **data, const char *fmt, va_list ap)
{
    const char *f;
    const void *par;
    const char *str_val;
    const struct p9_qid *qid;
    unsigned int len;
    unsigned int array_sz = 0;
    unsigned int elem_sz = 0;

    for ( f = fmt; *f; f++ )
    {
        if ( !array_sz )
            par = va_arg(ap, const void *);
        else
        {
            par += elem_sz;
            array_sz--;
        }

        switch ( *f )
        {
        case 'a':
            f++;
            if ( !*f || array_sz )
                fmt_err(fmt);
            array_sz = *(const unsigned int *)par;
            if ( array_sz > 0xffff )
            {
                syslog(LOG_CRIT, "array size %u in fill_buffer()", array_sz);
                exit(1);
            }
            put_unaligned(array_sz, (uint16_t *)*data);
            *data += sizeof(uint16_t);
            par = va_arg(ap, const void *);
            elem_sz = 0;
            break;

        case 'b':
            put_unaligned(*(const uint8_t *)par, (uint8_t *)*data);
            elem_sz = sizeof(uint8_t);
            *data += sizeof(uint8_t);
            break;

        case 'u':
            put_unaligned(*(const uint16_t *)par, (uint16_t *)*data);
            elem_sz = sizeof(uint16_t);
            *data += sizeof(uint16_t);
            break;

        case 'D':
            if ( array_sz )
                fmt_err(fmt);
            len = *(const unsigned int *)par;
            put_unaligned(len, (uint32_t *)*data);
            *data += sizeof(uint32_t);
            par = va_arg(ap, const void *);
            if ( *data != par )
                memcpy(*data, par, len);
            *data += len;
            break;

        case 'L':
            put_unaligned(*(const uint64_t *)par, (uint64_t *)*data);
            elem_sz = sizeof(uint64_t);
            *data += sizeof(uint64_t);
            break;

        case 'Q':
            qid = par;
            elem_sz = sizeof(*qid);
            fill_buffer_at(data, "bUL", &qid->type, &qid->version, &qid->path);
            break;

        case 'S':
            str_val = par;
            elem_sz = sizeof(str_val);
            len = strlen(str_val);
            if ( len > 0xffff )
            {
                syslog(LOG_CRIT, "string length %u in fill_buffer()", len);
                exit(1);
            }
            put_unaligned(len, (uint16_t *)*data);
            *data += sizeof(uint16_t);
            memcpy(*data, str_val, len);
            *data += len;
            break;

        case 'U':
            put_unaligned(*(const uint32_t *)par, (uint32_t *)*data);
            elem_sz = sizeof(uint32_t);
            *data += sizeof(uint32_t);
            break;

        default:
            fmt_err(fmt);
        }

        if ( array_sz )
            f--;
    }
}

static void fill_buffer_at(void **data, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfill_buffer_at(data, fmt, ap);
    va_end(ap);
}

static void fill_buffer(struct ring *ring, uint8_t cmd, uint16_t tag,
                        const char *fmt, ...)
{
    struct p9_header *hdr = ring->buffer;
    void *data = hdr + 1;
    va_list ap;

    hdr->cmd = cmd;
    hdr->tag = tag;

    va_start(ap, fmt);
    vfill_buffer_at(&data, fmt, ap);
    va_end(ap);

    hdr->size = data - ring->buffer;
}

static unsigned int add_string(struct ring *ring, const char *str,
                               unsigned int len)
{
    char *tmp;
    unsigned int ret;

    if ( ring->str_used + len + 1 > ring->str_size )
    {
        tmp = realloc(ring->str, ring->str_used + len + 1);
        if ( !tmp )
            return ~0;
        ring->str = tmp;
        ring->str_size = ring->str_used + len + 1;
    }

    ret = ring->str_used;
    memcpy(ring->str + ret, str, len);
    ring->str_used += len;
    ring->str[ring->str_used++] = 0;

    return ret;
}

static bool chk_data(struct ring *ring, void *data, unsigned int len)
{
    struct p9_header *hdr = ring->buffer;

    if ( data + len <= ring->buffer + hdr->size )
        return true;

    errno = E2BIG;

    return false;
}

static bool fill_data_elem(void **par, void **array, unsigned int *array_sz,
                           unsigned int elem_sz, void *data)
{
    if ( *array_sz && !*array )
    {
        *array = calloc(*array_sz, elem_sz);
        if ( !*array )
            return false;
        *par = *array;
    }

    memcpy(*par, data, elem_sz);

    if ( *array_sz )
    {
        *par += elem_sz;
        *array_sz -= 1;
    }

    return true;
}

/*
 * Fill variables with request data.
 * fmt is a sequence of format characters. Supported characters are:
 * a: an array (2 bytes number of elements + the following format as elements)
 *    The number of elements is stored in the first unsigned int parameter, the
 *    next parameter is a pointer to an array of elements as denoted by the next
 *    format character. The array is allocated dynamically.
 * b: 1 byte unsigned integer
 *    The value is stored in the next parameter with type uint8_t.
 * D: Data blob (4 byte length + <length> bytes)
 *    2 parameters are consumed, first an unsigned int for the length, then a
 *    pointer to the first uint8_t value.
 *    No array support.
 * L: 8 byte unsigned integer
 *    The value is stored in the next parameter with type uint64_t.
 * S: String (2 byte length + <length> characters)
 *    The 0-terminated string is stored in device->str + off, off is stored in
 *    the next parameter with type unsigned int.
 * U: 4 byte unsigned integer
 *    The value is stored in the next parameter with type uint32_t.
 *
 * Return value: number of filled variables, errno will be set in case of
 *   error.
 */
static int fill_data(struct ring *ring, const char *fmt, ...)
{
    struct p9_header *hdr = ring->buffer;
    void *data = hdr + 1;
    void *par;
    unsigned int pars = 0;
    const char *f;
    va_list ap;
    unsigned int len;
    unsigned int str_off;
    unsigned int array_sz = 0;
    void **array = NULL;

    va_start(ap, fmt);

    for ( f = fmt; *f; f++ )
    {
        if ( !array_sz )
            par = va_arg(ap, void *);

        switch ( *f )
        {
        case 'a':
            f++;
            if ( !*f || array_sz )
                fmt_err(fmt);
            if ( !chk_data(ring, data, sizeof(uint16_t)) )
                return pars;
            array_sz = get_unaligned((uint16_t *)data);
            data += sizeof(uint16_t);
            *(unsigned int *)par = array_sz;
            array = va_arg(ap, void **);
            *array = NULL;
            break;

        case 'b':
            if ( !chk_data(ring, data, sizeof(uint8_t)) )
                return pars;
            if ( !fill_data_elem(&par, array, &array_sz, sizeof(uint8_t),
                                 data) )
                return pars;
            data += sizeof(uint8_t);
            break;

        case 'D':
            if ( array_sz )
                fmt_err(fmt);
            if ( !chk_data(ring, data, sizeof(uint32_t)) )
                return pars;
            len = get_unaligned((uint32_t *)data);
            data += sizeof(uint32_t);
            *(unsigned int *)par = len;
            par = va_arg(ap, void *);
            if ( !chk_data(ring, data, len) )
                return pars;
            memcpy(par, data, len);
            data += len;
            break;

        case 'L':
            if ( !chk_data(ring, data, sizeof(uint64_t)) )
                return pars;
            if ( !fill_data_elem(&par, array, &array_sz, sizeof(uint64_t),
                                 data) )
                return pars;
            data += sizeof(uint64_t);
            break;

        case 'S':
            if ( !chk_data(ring, data, sizeof(uint16_t)) )
                return pars;
            len = get_unaligned((uint16_t *)data);
            data += sizeof(uint16_t);
            if ( !chk_data(ring, data, len) )
                return pars;
            str_off = add_string(ring, data, len);
            if ( str_off == ~0 )
                return pars;
            if ( !fill_data_elem(&par, array, &array_sz, sizeof(unsigned int),
                                 &str_off) )
                return pars;
            data += len;
            break;

        case 'U':
            if ( !chk_data(ring, data, sizeof(uint32_t)) )
                return pars;
            if ( !fill_data_elem(&par, array, &array_sz, sizeof(uint32_t),
                                 data) )
                return pars;
            data += sizeof(uint32_t);
            break;

        default:
            fmt_err(fmt);
        }

        if ( array_sz )
            f--;
        pars++;
    }

    return pars;
}

static void p9_error(struct ring *ring, uint16_t tag, uint32_t err)
{
    unsigned int erroff;

    strerror_r(err, ring->buffer, ring->ring_size);
    erroff = add_string(ring, ring->buffer, strlen(ring->buffer));
    fill_buffer(ring, P9_CMD_ERROR, tag, "SU",
                erroff != ~0 ? ring->str + erroff : "cannot allocate memory",
                &err);
}

static void p9_version(struct ring *ring, struct p9_header *hdr)
{
    uint32_t max_size;
    unsigned int off;
    char *version;
    int ret;

    ret = fill_data(ring, "US", &max_size, &off);
    if ( ret != 2 )
    {
        p9_error(ring, hdr->tag, errno);
        return;
    }

    if ( max_size < P9_MIN_MSIZE )
    {
        p9_error(ring, hdr->tag, EMSGSIZE);
        return;
    }

    if ( max_size < ring->max_size )
        ring->max_size = max_size;

    version = ring->str + off;
    if ( strcmp(version, P9_VERSION) )
        version = "unknown";

    fill_buffer(ring, hdr->cmd + 1, hdr->tag, "US", &ring->max_size, version);
}

void *io_thread(void *arg)
{
    struct ring *ring = arg;
    unsigned int count = 0;
    struct p9_header hdr = { .size = 0 };
    bool in_hdr = true;

    ring->max_size = ring->ring_size;
    ring->buffer = malloc(ring->max_size);
    if ( !ring->buffer )
    {
        syslog(LOG_CRIT, "memory allocation failure!");
        return NULL;
    }

    while ( !ring->stop_thread )
    {
        pthread_mutex_lock(&ring->mutex);
        if ( !io_work_pending(ring) )
        {
            if ( !ring->error && xenevtchn_unmask(xe, ring->evtchn) < 0 )
                syslog(LOG_WARNING, "xenevtchn_unmask() failed");
            pthread_cond_wait(&ring->cond, &ring->mutex);
        }
        pthread_mutex_unlock(&ring->mutex);

        if ( ring->stop_thread || ring->error )
            continue;

        if ( !ring->handle_response )
        {
            if ( in_hdr )
            {
                count += get_request_bytes(ring, count, sizeof(hdr));
                if ( count != sizeof(hdr) )
                    continue;
                hdr = *(struct p9_header *)ring->buffer;
                if ( hdr.size > ring->max_size || hdr.size < sizeof(hdr) )
                {
                    syslog(LOG_ERR, "%u.%u specified illegal request length %u",
                           ring->device->domid, ring->device->devid, hdr.size);
                    ring->error = true;
                    continue;
                }
                in_hdr = false;
            }

            count += get_request_bytes(ring, count, hdr.size);
            if ( count < hdr.size )
                continue;

            ring->str_used = 0;

            switch ( hdr.cmd )
            {
            case P9_CMD_VERSION:
                p9_version(ring, &hdr);
                break;

            default:
                syslog(LOG_DEBUG, "%u.%u sent unhandled command %u\n",
                       ring->device->domid, ring->device->devid, hdr.cmd);
                p9_error(ring, hdr.tag, EOPNOTSUPP);
                break;
            }

            ring->handle_response = true;
            hdr.size = ((struct p9_header *)ring->buffer)->size;
            count = 0;
        }

        if ( ring->handle_response )
        {
            count += put_response_bytes(ring, count, hdr.size);

            if ( count == hdr.size )
            {
                /* Signal presence of response. */
                xenevtchn_notify(xe, ring->evtchn);

                ring->handle_response = false;
                in_hdr = true;
                count = 0;
            }
        }
    }

    free(ring->str);
    free(ring->buffer);

    ring->thread_active = false;

    return NULL;
}
