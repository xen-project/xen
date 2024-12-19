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

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <xen-barrier.h>
#include <xen-tools/common-macros.h>

#include "xen-9pfsd.h"

/* P9 protocol commands (response is either cmd+1 or P9_CMD_ERROR). */
#define P9_CMD_VERSION    100
#define P9_CMD_ATTACH     104
#define P9_CMD_ERROR      107
#define P9_CMD_WALK       110
#define P9_CMD_OPEN       112
#define P9_CMD_CREATE     114
#define P9_CMD_READ       116
#define P9_CMD_WRITE      118
#define P9_CMD_CLUNK      120
#define P9_CMD_STAT       124

/* P9 protocol open flags. */
#define P9_OREAD            0   /* read */
#define P9_OWRITE           1   /* write */
#define P9_ORDWR            2   /* read and write */
#define P9_OMODEMASK     0x03
#define P9_OTRUNC        0x10   /* or'ed in, truncate file first */
#define P9_OREMOVE       0x40   /* or'ed in, remove file after clunk */

/* P9 protocol create permission masks. */
#define P9_CREATE_PERM_DIR        0x80000000
#define P9_CREATE_PERM_NOTSUPP    0x03b00000   /* link, symlink, ... */
#define P9_CREATE_PERM_DIR_MASK   0777
#define P9_CREATE_PERM_FILE_MASK  0666

#define P9_MIN_MSIZE      2048
#define P9_VERSION        "9P2000.u"
#define P9_WALK_MAXELEM   16

struct p9_qid {
    uint8_t type;
#define QID_TYPE_DIR      0x80
    uint32_t version;
    uint64_t path;
};

struct p9_stat {
    uint16_t size;
    uint16_t type;
    uint32_t dev;
    struct p9_qid qid;
    uint32_t mode;
    uint32_t atime;
    uint32_t mtime;
    uint64_t length;
    const char *name;
    const char *uid;
    const char *gid;
    const char *muid;
    const char *extension;
    uint32_t n_uid;
    uint32_t n_gid;
    uint32_t n_muid;
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
 * s: stat (struct p9_stat)
 * U: 4 byte unsigned integer
 *    The parameter is a pointer to a uint32_t value
 */
static void fill_buffer_at(void **data, const char *fmt, ...);
static void vfill_buffer_at(void **data, const char *fmt, va_list ap)
{
    const char *f;
    const void *par = NULL; /* old gcc */
    const char *str_val;
    const struct p9_qid *qid;
    const struct p9_stat *stat;
    uint16_t tlen;
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

        case 's':
            stat = par;
            elem_sz = sizeof(*stat);
            tlen = stat->size + sizeof(stat->size);
            fill_buffer_at(data, "uuuUQUUULSSSSSUUU", &tlen, &stat->size,
                           &stat->type, &stat->dev, &stat->qid, &stat->mode,
                           &stat->atime, &stat->mtime, &stat->length,
                           stat->name, stat->uid, stat->gid, stat->muid,
                           stat->extension, &stat->n_uid, &stat->n_gid,
                           &stat->n_muid);
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
                goto out;
            array_sz = get_unaligned((uint16_t *)data);
            data += sizeof(uint16_t);
            *(unsigned int *)par = array_sz;
            array = va_arg(ap, void **);
            *array = NULL;
            break;

        case 'b':
            if ( !chk_data(ring, data, sizeof(uint8_t)) )
                goto out;
            if ( !fill_data_elem(&par, array, &array_sz, sizeof(uint8_t),
                                 data) )
                goto out;
            data += sizeof(uint8_t);
            break;

        case 'D':
            if ( array_sz )
                fmt_err(fmt);
            if ( !chk_data(ring, data, sizeof(uint32_t)) )
                goto out;
            len = get_unaligned((uint32_t *)data);
            data += sizeof(uint32_t);
            *(unsigned int *)par = len;
            par = va_arg(ap, void *);
            if ( !chk_data(ring, data, len) )
                goto out;
            memcpy(par, data, len);
            data += len;
            break;

        case 'L':
            if ( !chk_data(ring, data, sizeof(uint64_t)) )
                goto out;
            if ( !fill_data_elem(&par, array, &array_sz, sizeof(uint64_t),
                                 data) )
                goto out;
            data += sizeof(uint64_t);
            break;

        case 'S':
            if ( !chk_data(ring, data, sizeof(uint16_t)) )
                goto out;
            len = get_unaligned((uint16_t *)data);
            data += sizeof(uint16_t);
            if ( !chk_data(ring, data, len) )
                goto out;
            str_off = add_string(ring, data, len);
            if ( str_off == ~0 )
                goto out;
            if ( !fill_data_elem(&par, array, &array_sz, sizeof(unsigned int),
                                 &str_off) )
                goto out;
            data += len;
            break;

        case 'U':
            if ( !chk_data(ring, data, sizeof(uint32_t)) )
                goto out;
            if ( !fill_data_elem(&par, array, &array_sz, sizeof(uint32_t),
                                 data) )
                goto out;
            data += sizeof(uint32_t);
            break;

        default:
            fmt_err(fmt);
        }

        if ( array_sz )
            f--;
        pars++;
    }

 out:
    va_end(ap);

    return pars;
}

static struct p9_fid *find_fid(device *device, unsigned int fid)
{
    struct p9_fid *fidp;

    XEN_TAILQ_FOREACH(fidp, &device->fids, list)
    {
        if ( fidp->fid == fid )
            return fidp;
    }

    return NULL;
}

static struct p9_fid *get_fid_ref(device *device, unsigned int fid)
{
    struct p9_fid *fidp;

    pthread_mutex_lock(&device->fid_mutex);

    fidp = find_fid(device, fid);
    if ( fidp )
        fidp->ref++;

    pthread_mutex_unlock(&device->fid_mutex);

    return fidp;
}

static struct p9_fid *alloc_fid_mem(device *device, unsigned int fid,
                                    const char *path)
{
    struct p9_fid *fidp;

    fidp = calloc(sizeof(*fidp) + strlen(path) + 1, 1);
    if ( !fidp )
        return NULL;

    fidp->fid = fid;
    strcpy(fidp->path, path);

    return fidp;
}

static struct p9_fid *alloc_fid(device *device, unsigned int fid,
                                const char *path)
{
    struct p9_fid *fidp = NULL;

    pthread_mutex_lock(&device->fid_mutex);

    if ( find_fid(device, fid) )
    {
        errno = EBADF;
        goto out;
    }

    if ( device->n_fids >= device->max_open_files )
    {
        errno = EMFILE;
        goto out;
    }

    fidp = alloc_fid_mem(device, fid, path);
    if ( !fidp )
        goto out;

    fidp->ref = 1;
    XEN_TAILQ_INSERT_HEAD(&device->fids, fidp, list);
    device->n_fids++;

 out:
    pthread_mutex_unlock(&device->fid_mutex);

    return fidp;
}

static void free_fid(device *device, struct p9_fid *fidp)
{
    if ( !fidp )
        return;

    pthread_mutex_lock(&device->fid_mutex);

    fidp->ref--;
    if ( !fidp->ref )
    {
        device->n_fids--;
        XEN_TAILQ_REMOVE(&device->fids, fidp, list);
        free(fidp);
    }

    pthread_mutex_unlock(&device->fid_mutex);
}

void free_fids(device *device)
{
    struct p9_fid *fidp;

    while ( (fidp = XEN_TAILQ_FIRST(&device->fids)) != NULL )
    {
        XEN_TAILQ_REMOVE(&device->fids, fidp, list);
        free(fidp);
    }
}

static const char *relpath_from_path(const char *path)
{
    if (!strcmp(path, "/"))
        return ".";

    return (path[0] == '/') ? path + 1 : path;
}

static int fill_qid(device *device, const char *path, struct p9_qid *qid,
                    const struct stat *stbuf)
{
    struct stat st;

    if ( !stbuf )
    {
        if ( fstatat(device->root_fd, path, &st, 0) )
            return errno;

        stbuf = &st;
    }

    /* Don't allow symbolic links. */
    if ( S_ISLNK(stbuf->st_mode) )
        return EMLINK;

    qid->type = S_ISDIR(stbuf->st_mode) ? QID_TYPE_DIR : 0;
    qid->version = stbuf->st_mtime ^ (stbuf->st_size << 8);
    qid->path = stbuf->st_ino;

    return 0;
}

static bool name_ok(const char *str)
{
    if ( !*str )
        return false;

    if ( strchr(str, '/' ) )
        return false;

    if ( !strcmp(str, "..") || !strcmp(str, ".") )
        return false;

    return true;
}

/* Including the '\0' */
#define MAX_ERRSTR_LEN 80
static void p9_error(struct ring *ring, uint16_t tag, uint32_t err)
{
    unsigned int erroff;
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    char *str;
    size_t len = 0;

    /*
     * While strerror_r() exists, it comes in a POSIX and a GNU flavor.
     * Let's try to avoid trying to be clever with determining which
     * one it is that the underlying C library offers, when really we
     * don't expect this function to be called very often.
     */
    pthread_mutex_lock(&mutex);
    str = strerror(err);
    len = min(strlen(str), (size_t)(MAX_ERRSTR_LEN - 1));
    memcpy(ring->buffer, str, len);
    ((char *)ring->buffer)[len] = '\0';
    pthread_mutex_unlock(&mutex);

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

static void p9_attach(struct ring *ring, struct p9_header *hdr)
{
    device *device = ring->device;
    uint32_t fid;
    uint32_t dummy_u32;
    unsigned int dummy_uint;
    struct p9_qid qid;
    int ret;

    ret = fill_data(ring, "UUSSU", &fid, &dummy_u32, &dummy_uint, &dummy_uint,
                    &dummy_u32);
    if ( ret != 5 )
    {
        p9_error(ring, hdr->tag, errno);
        return;
    }

    device->root_fid = alloc_fid(device, fid, relpath_from_path("/"));
    if ( !device->root_fid )
    {
        p9_error(ring, hdr->tag, errno);
        return;
    }

    ret = fill_qid(device, device->root_fid->path, &qid, NULL);
    if ( ret )
    {
        free_fid(device, device->root_fid);
        device->root_fid = NULL;
        p9_error(ring, hdr->tag, ret);
        return;
    }

    fill_buffer(ring, hdr->cmd + 1, hdr->tag, "Q", &qid);
}

static void p9_walk(struct ring *ring, struct p9_header *hdr)
{
    device *device = ring->device;
    uint32_t fid;
    uint32_t newfid;
    struct p9_fid *fidp = NULL;
    struct p9_qid *qids = NULL;
    unsigned int n_names = 0;
    unsigned int *names = NULL;
    unsigned int walked = 0;
    unsigned int i;
    char *path = NULL;
    unsigned int path_len;
    int ret;

    ret = fill_data(ring, "UUaS", &fid, &newfid, &n_names, &names);
    if ( n_names > P9_WALK_MAXELEM )
    {
        p9_error(ring, hdr->tag, EINVAL);
        goto out;
    }
    if ( ret != 3 + n_names )
    {
        p9_error(ring, hdr->tag, errno);
        goto out;
    }

    fidp = get_fid_ref(device, fid);
    if ( !fidp )
    {
        p9_error(ring, hdr->tag, ENOENT);
        goto out;
    }
    if ( fidp->opened )
    {
        p9_error(ring, hdr->tag, EINVAL);
        goto out;
    }

    path_len = strlen(fidp->path) + 1;
    for ( i = 0; i < n_names; i++ )
    {
        if ( !name_ok(ring->str + names[i]) )
        {
            p9_error(ring, hdr->tag, ENOENT);
            goto out;
        }
        path_len += strlen(ring->str + names[i]) + 1;
    }
    path = calloc(path_len + 1, 1);
    if ( !path )
    {
        p9_error(ring, hdr->tag, ENOMEM);
        goto out;
    }
    strcpy(path, fidp->path);

    if ( n_names )
    {
        qids = calloc(n_names, sizeof(*qids));
        if ( !qids )
        {
            p9_error(ring, hdr->tag, ENOMEM);
            goto out;
        }
        for ( i = 0; i < n_names; i++ )
        {
            strcat(path, "/");
            strcat(path, ring->str + names[i]);
            ret = fill_qid(device, path, qids + i, NULL);
            if ( ret )
            {
                if ( !walked )
                {
                    p9_error(ring, hdr->tag, errno);
                    goto out;
                }
                break;
            }
            walked++;
        }
    }

    if ( walked == n_names )
    {
        bool ok = false;

        if ( fid == newfid )
        {
            struct p9_fid *new_fidp;

            pthread_mutex_lock(&device->fid_mutex);

            if ( fidp->ref != 2 )
            {
                errno = EBUSY;
            }
            else
            {
                new_fidp = alloc_fid_mem(device, fid, path);
                if ( new_fidp )
                {
                    new_fidp->ref = 2;
                    XEN_TAILQ_REMOVE(&device->fids, fidp, list);
                    XEN_TAILQ_INSERT_HEAD(&device->fids, new_fidp, list);
                    free(fidp);
                    fidp = new_fidp;
                    ok = true;
                }
            }

            pthread_mutex_unlock(&device->fid_mutex);
        }
        else
            ok = alloc_fid(device, newfid, path);

        if ( !ok )
        {
            p9_error(ring, hdr->tag, errno);
            goto out;
        }
    }

    fill_buffer(ring, hdr->cmd + 1, hdr->tag, "aQ", &walked, qids);

 out:
    free_fid(device, fidp);
    free(qids);
    free(path);
    free(names);
}

static int open_flags_from_mode(uint8_t mode)
{
    int flags;

    switch ( mode & P9_OMODEMASK )
    {
    case P9_OREAD:
        flags = O_RDONLY;
        break;

    case P9_OWRITE:
        flags = O_WRONLY;
        break;

    case P9_ORDWR:
        flags = O_RDWR;
        break;

    default:
        errno = EINVAL;
        return -1;
    }

    if ( mode & P9_OTRUNC )
        flags |= O_TRUNC;

    return flags;
}

static unsigned int get_iounit(struct ring *ring, struct stat *st)
{
    return (ring->max_size - st->st_blksize) & ~(st->st_blksize - 1);
}

static void p9_open(struct ring *ring, struct p9_header *hdr)
{
    device *device = ring->device;
    uint32_t fid;
    uint8_t mode;
    struct p9_fid *fidp;
    struct stat st;
    struct p9_qid qid;
    uint32_t iounit;
    int flags;
    int ret;

    ret = fill_data(ring, "Ub", &fid, &mode);
    if ( ret != 2 )
    {
        p9_error(ring, hdr->tag, EINVAL);
        return;
    }
    if ( mode & ~(P9_OMODEMASK | P9_OTRUNC | P9_OREMOVE) )
    {
        p9_error(ring, hdr->tag, EINVAL);
        return;
    }

    fidp = get_fid_ref(device, fid);
    if ( !fidp )
    {
        p9_error(ring, hdr->tag, ENOENT);
        return;
    }
    if ( fidp->opened )
    {
        errno = EINVAL;
        goto err;
    }

    if ( fstatat(device->root_fd, fidp->path, &st, 0) < 0 )
    {
        errno = ENOENT;
        goto err;
    }

    if ( S_ISLNK(st.st_mode) )
    {
        errno = EMLINK;
        goto err;
    }

    fidp->isdir = S_ISDIR(st.st_mode);
    fidp->mode = mode;
    if ( fidp->isdir )
    {
        if ( mode != P9_OREAD )
        {
            errno = EINVAL;
            goto err;
        }
        fidp->fd = openat(device->root_fd, fidp->path, O_RDONLY);
        if ( fidp->fd < 0 )
            goto err;
        fidp->data = fdopendir(fidp->fd);
        if ( !fidp->data )
            goto err;
    }
    else
    {
        flags = open_flags_from_mode(mode);
        if ( flags < 0 )
            goto err;

        fidp->fd = openat(device->root_fd, fidp->path, flags);
        if ( fidp->fd < 0 )
            goto err;
    }

    fill_qid(device, fidp->path, &qid, &st);
    iounit = get_iounit(ring, &st);
    fidp->opened = true;

    fill_buffer(ring, hdr->cmd + 1, hdr->tag, "QU", &qid, &iounit);

    return;

 err:
    free_fid(device, fidp);
    p9_error(ring, hdr->tag, errno);
}

static void p9_create(struct ring *ring, struct p9_header *hdr)
{
    device *device = ring->device;
    uint32_t fid;
    unsigned int name_off;
    uint32_t perm;
    uint8_t mode;
    unsigned int ext_off;
    struct p9_fid *fidp;
    struct p9_fid *new_fidp;
    char *path;
    struct stat st;
    struct p9_qid qid;
    uint32_t iounit;
    int flags;
    int ret;

    ret = fill_data(ring, "USUbS", &fid, &name_off, &perm, &mode, &ext_off);
    if ( ret != 5 )
    {
        p9_error(ring, hdr->tag, EINVAL);
        return;
    }

    if ( !name_ok(ring->str + name_off) )
    {
        p9_error(ring, hdr->tag, ENOENT);
        return;
    }

    if ( perm & P9_CREATE_PERM_NOTSUPP )
    {
        p9_error(ring, hdr->tag, EINVAL);
        return;
    }

    fidp = get_fid_ref(device, fid);
    if ( !fidp || fidp->opened )
    {
        free_fid(device, fidp);
        p9_error(ring, hdr->tag, EINVAL);
        return;
    }
    if ( fstatat(device->root_fd, fidp->path, &st, 0) < 0 )
    {
        free_fid(device, fidp);
        p9_error(ring, hdr->tag, errno);
        return;
    }

    path = malloc(strlen(fidp->path) + strlen(ring->str + name_off) + 2);
    if ( !path )
    {
        free_fid(device, fidp);
        p9_error(ring, hdr->tag, ENOMEM);
        return;
    }
    sprintf(path, "%s/%s", fidp->path, ring->str + name_off);
    new_fidp = alloc_fid_mem(device, fid, path);
    free(path);
    if ( !new_fidp )
    {
        free_fid(device, fidp);
        p9_error(ring, hdr->tag, ENOMEM);
        return;
    }

    pthread_mutex_lock(&device->fid_mutex);

    new_fidp->ref = fidp->ref;

    if ( perm & P9_CREATE_PERM_DIR )
    {
        perm &= P9_CREATE_PERM_DIR_MASK & st.st_mode;
        if ( mode != P9_OREAD )
        {
            errno = EINVAL;
            goto err;
        }
        if ( mkdirat(device->root_fd, new_fidp->path, perm) < 0 )
            goto err;

        XEN_TAILQ_REMOVE(&device->fids, fidp, list);
        XEN_TAILQ_INSERT_HEAD(&device->fids, new_fidp, list);
        free(fidp);
        fidp = new_fidp;
        new_fidp = NULL;

        fidp->fd = openat(device->root_fd, fidp->path, O_RDONLY);
        if ( fidp->fd < 0 )
            goto err;
        fidp->data = fdopendir(fidp->fd);
        if ( !fidp->data )
            goto err;
    }
    else
    {
        flags = open_flags_from_mode(mode);
        if ( flags < 0 )
        {
            errno = EINVAL;
            goto err;
        }
        perm &= P9_CREATE_PERM_FILE_MASK & st.st_mode;

        XEN_TAILQ_REMOVE(&device->fids, fidp, list);
        XEN_TAILQ_INSERT_HEAD(&device->fids, new_fidp, list);
        free(fidp);
        fidp = new_fidp;
        new_fidp = NULL;

        fidp->fd = openat(device->root_fd, fidp->path, flags | O_CREAT | O_EXCL,
                          perm);
        if ( fidp->fd < 0 )
            goto err;
    }

    if ( fstatat(device->root_fd, fidp->path, &st, 0) < 0 )
        goto err;

    fill_qid(device, fidp->path, &qid, &st);
    iounit = get_iounit(ring, &st);
    fidp->opened = true;
    fidp->mode = mode;

    pthread_mutex_unlock(&device->fid_mutex);

    fill_buffer(ring, hdr->cmd + 1, hdr->tag, "QU", &qid, &iounit);

    return;

 err:
    p9_error(ring, hdr->tag, errno);

    pthread_mutex_unlock(&device->fid_mutex);

    free(new_fidp);
    free_fid(device, fidp);
}

static void p9_clunk(struct ring *ring, struct p9_header *hdr)
{
    device *device = ring->device;
    uint32_t fid;
    struct p9_fid *fidp;
    int ret;

    ret = fill_data(ring, "U", &fid);
    if ( ret != 1 )
    {
        p9_error(ring, hdr->tag, EINVAL);
        return;
    }

    fidp = get_fid_ref(device, fid);
    if ( !fidp )
    {
        p9_error(ring, hdr->tag, ENOENT);
        return;
    }

    if ( fidp->opened )
    {
        fidp->opened = false;
        free_fid(device, fidp);
        close(fidp->fd);
        if ( fidp->mode & P9_OREMOVE )
            unlinkat(device->root_fd, fidp->path,
                     fidp->isdir ? AT_REMOVEDIR : 0);
    }

    /* 2 calls of free_fid(): one for our reference, and one to free it. */
    free_fid(device, fidp);
    free_fid(device, fidp);

    fill_buffer(ring, hdr->cmd + 1, hdr->tag, "");
}

static void fill_p9_stat(device *device, struct p9_stat *p9s, struct stat *st,
                         const char *name)
{
    memset(p9s, 0, sizeof(*p9s));
    fill_qid(device, NULL, &p9s->qid, st);
    p9s->mode = st->st_mode & 0777;
    if ( S_ISDIR(st->st_mode) )
        p9s->mode |= P9_CREATE_PERM_DIR;
    p9s->atime = st->st_atime;
    p9s->mtime = st->st_mtime;
    p9s->length = st->st_size;
    p9s->name = name;
    p9s->uid = "";
    p9s->gid = "";
    p9s->muid = "";
    p9s->extension = "";
    p9s->n_uid = 0;
    p9s->n_gid = 0;
    p9s->n_muid = 0;

    /*
     * Size of individual fields without the size field, including 5 2-byte
     * string length fields.
     */
    p9s->size = 71 + strlen(p9s->name);
}

static void p9_stat(struct ring *ring, struct p9_header *hdr)
{
    device *device = ring->device;
    uint32_t fid;
    struct p9_fid *fidp;
    struct p9_stat p9s;
    struct stat st;
    int ret;

    ret = fill_data(ring, "U", &fid);
    if ( ret != 1 )
    {
        p9_error(ring, hdr->tag, EINVAL);
        return;
    }

    fidp = get_fid_ref(device, fid);
    if ( !fidp )
    {
        p9_error(ring, hdr->tag, ENOENT);
        return;
    }

    if ( fstatat(device->root_fd, fidp->path, &st, 0) < 0 )
    {
        p9_error(ring, hdr->tag, errno);
        goto out;
    }
    fill_p9_stat(device, &p9s, &st, strrchr(fidp->path, '/') + 1);

    fill_buffer(ring, hdr->cmd + 1, hdr->tag, "s", &p9s);

 out:
    free_fid(device, fidp);
}

static void p9_read(struct ring *ring, struct p9_header *hdr)
{
    device *device = ring->device;
    uint32_t fid;
    uint64_t off;
    unsigned int len;
    uint32_t count;
    void *buf;
    struct p9_fid *fidp;
    int ret;

    ret = fill_data(ring, "ULU", &fid, &off, &count);
    if ( ret != 3 )
    {
        p9_error(ring, hdr->tag, EINVAL);
        return;
    }

    fidp = get_fid_ref(device, fid);
    if ( !fidp || !fidp->opened )
    {
        errno = EBADF;
        goto err;
    }

    len = count;
    buf = ring->buffer + sizeof(*hdr) + sizeof(uint32_t);

    if ( fidp->isdir )
    {
        struct dirent *dirent;
        struct stat st;
        struct p9_stat p9s;

        if ( off == 0 )
            rewinddir(fidp->data);

        while ( len != 0 )
        {
            errno = 0;
            dirent = readdir(fidp->data);
            if ( !dirent )
            {
                if ( errno )
                    goto err;
                break;
            }
            if ( fstatat(fidp->fd, dirent->d_name, &st, 0) < 0 )
                goto err;
            fill_p9_stat(device, &p9s, &st, dirent->d_name);
            if ( p9s.size + sizeof(p9s.size) > len )
            {
                seekdir(fidp->data, dirent->d_off);
                break;
            }
            fill_buffer_at(&buf, "s", &p9s);
            len -= p9s.size + sizeof(p9s.size);
        }
    }
    else
    {
        while ( len != 0 )
        {
            ret = pread(fidp->fd, buf, len, off);
            if ( ret <= 0 )
                break;
            len -= ret;
            buf += ret;
            off += ret;
        }
        if ( ret < 0 && len == count )
            goto err;
    }

    buf = ring->buffer + sizeof(*hdr) + sizeof(uint32_t);
    len = count - len;
    fill_buffer(ring, hdr->cmd + 1, hdr->tag, "D", &len, buf);

 out:
    free_fid(device, fidp);

    return;

 err:
    p9_error(ring, hdr->tag, errno);
    goto out;
}

static void p9_write(struct ring *ring, struct p9_header *hdr)
{
    device *device = ring->device;
    uint32_t fid;
    uint64_t off;
    unsigned int len;
    uint32_t written;
    void *buf;
    struct p9_fid *fidp;
    int ret;

    ret = fill_data(ring, "ULD", &fid, &off, &len, ring->buffer);
    if ( ret != 3 )
    {
        p9_error(ring, hdr->tag, EINVAL);
        return;
    }

    fidp = get_fid_ref(device, fid);
    if ( !fidp || !fidp->opened || fidp->isdir )
    {
        p9_error(ring, hdr->tag, EBADF);
        goto out;
    }

    buf = ring->buffer;

    while ( len != 0 )
    {
        ret = pwrite(fidp->fd, buf, len, off);
        if ( ret < 0 )
            break;
        len -= ret;
        buf += ret;
        off += ret;
    }

    written = buf - ring->buffer;
    if ( written == 0 )
    {
        p9_error(ring, hdr->tag, errno);
        goto out;
    }
    fill_buffer(ring, hdr->cmd + 1, hdr->tag, "U", &written);

 out:
    free_fid(device, fidp);
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

            case P9_CMD_ATTACH:
                p9_attach(ring, &hdr);
                break;

            case P9_CMD_WALK:
                p9_walk(ring, &hdr);
                break;

            case P9_CMD_OPEN:
                p9_open(ring, &hdr);
                break;

            case P9_CMD_CREATE:
                p9_create(ring, &hdr);
                break;

            case P9_CMD_READ:
                p9_read(ring, &hdr);
                break;

            case P9_CMD_WRITE:
                p9_write(ring, &hdr);
                break;

            case P9_CMD_CLUNK:
                p9_clunk(ring, &hdr);
                break;

            case P9_CMD_STAT:
                p9_stat(ring, &hdr);
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
