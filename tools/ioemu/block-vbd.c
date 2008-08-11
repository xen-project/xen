/*
 * Block driver for Mini-os PV devices
 * Based on block-raw.c
 * 
 * Copyright (c) 2006 Fabrice Bellard, 2007 Samuel Thibault
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "vl.h"
#include "block_int.h"
#include <assert.h>
#include <xenbus.h>
#include <blkfront.h>
#include <malloc.h>

#define SECTOR_SIZE 512

#ifndef QEMU_TOOL
#include "exec-all.h"
#endif

#define DEBUG_BLOCK
#ifdef  DEBUG_BLOCK
#define DEBUG_BLOCK_PRINT( formatCstr, args... ) fprintf( logfile, formatCstr, ##args ); fflush( logfile )
#else
#define DEBUG_BLOCK_PRINT( formatCstr, args... )
#endif

#define FTYPE_FILE   0
#define FTYPE_CD     1
#define FTYPE_FD     2

typedef struct BDRVVbdState {
    struct blkfront_dev *dev;
    int fd;
    struct blkfront_info info;
    LIST_ENTRY(BDRVVbdState) list;
} BDRVVbdState;

LIST_HEAD(, BDRVVbdState) vbds;

static int vbd_probe(const uint8_t *buf, int buf_size, const char *filename)
{
    char *value;
    if (xenbus_read(XBT_NIL, filename, &value))
	return 0;
    free(value);
    return 100;
}

static void vbd_io_completed(void *opaque)
{
    BDRVVbdState *s = opaque;
    blkfront_aio_poll(s->dev);
}

static int vbd_open(BlockDriverState *bs, const char *filename, int flags)
{
    BDRVVbdState *s = bs->opaque;

    //handy to test posix access
    //return -EIO;

    s->dev = init_blkfront((char *) filename, &s->info);

    if (!s->dev)
	return -EIO;

    if (SECTOR_SIZE % s->info.sector_size) {
	printf("sector size is %d, we only support sector sizes that divide %d\n", s->info.sector_size, SECTOR_SIZE);
	return -EIO;
    }

    s->fd = blkfront_open(s->dev);
    qemu_set_fd_handler(s->fd, vbd_io_completed, NULL, s);

    LIST_INSERT_HEAD(&vbds, s, list);

    return 0;
}

typedef struct VbdAIOCB {
    BlockDriverAIOCB common;
    struct blkfront_aiocb aiocb;
} VbdAIOCB;

void qemu_aio_init(void)
{
}

void qemu_aio_poll(void)
{
}

/* Wait for all IO requests to complete.  */
void qemu_aio_flush(void)
{
    BDRVVbdState *s;
    for (s = vbds.lh_first; s; s = s->list.le_next)
	blkfront_sync(s->dev);
}

void qemu_aio_wait_start(void)
{
}

void qemu_aio_wait(void)
{
    int some = 0;
    DEFINE_WAIT(w);
    while (1) {
	BDRVVbdState *s;
	add_waiter(w, blkfront_queue);
        for (s = vbds.lh_first; s; s = s->list.le_next)
	    if (blkfront_aio_poll(s->dev))
		some = 1;
	if (some)
	    break;
	schedule();
    }
    remove_waiter(w);
}

void qemu_aio_wait_end(void)
{
}

static void vbd_aio_callback(struct blkfront_aiocb *aiocbp, int ret) {
    VbdAIOCB *acb = aiocbp->data;

    acb->common.cb(acb->common.opaque, ret);
    qemu_aio_release(acb);
}

static VbdAIOCB *vbd_aio_setup(BlockDriverState *bs,
        int64_t sector_num, uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    BDRVVbdState *s = bs->opaque;
    VbdAIOCB *acb;

    acb = qemu_aio_get(bs, cb, opaque);
    if (!acb)
	return NULL;
    acb->aiocb.aio_dev = s->dev;
    acb->aiocb.aio_buf = buf;
    acb->aiocb.aio_nbytes = nb_sectors * SECTOR_SIZE;
    acb->aiocb.aio_offset = sector_num * SECTOR_SIZE;
    acb->aiocb.aio_cb = vbd_aio_callback;
    acb->aiocb.data = acb;

    return acb;
}

static BlockDriverAIOCB *vbd_aio_read(BlockDriverState *bs,
        int64_t sector_num, uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    VbdAIOCB *acb;

    acb = vbd_aio_setup(bs, sector_num, buf, nb_sectors, cb, opaque);
    if (!acb)
	return NULL;
    blkfront_aio(&acb->aiocb, 0);
    return &acb->common;
}

static BlockDriverAIOCB *vbd_aio_write(BlockDriverState *bs,
        int64_t sector_num, const uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    VbdAIOCB *acb;

    acb = vbd_aio_setup(bs, sector_num, (uint8_t*) buf, nb_sectors, cb, opaque);
    if (!acb)
	return NULL;
    blkfront_aio(&acb->aiocb, 1);
    return &acb->common;
}

static void vbd_cb(void *data, int ret) {
    int *result = data;
    result[0] = 1;
    result[1] = ret;
}

static int vbd_aligned_io(BlockDriverState *bs,
	int64_t sector_num, uint8_t *buf, int nb_sectors, int write)
{
    VbdAIOCB *acb;
    int result[2];
    result[0] = 0;
    qemu_aio_wait_start();
    acb = vbd_aio_setup(bs, sector_num, (uint8_t*) buf, nb_sectors, vbd_cb, &result);
    blkfront_aio(&acb->aiocb, write);
    while (!result[0])
	qemu_aio_wait();
    qemu_aio_wait_end();
    return result[1];
}

static int vbd_read(BlockDriverState *bs,
	int64_t sector_num, uint8_t *buf, int nb_sectors)
{
    uint8_t *iobuf;
    int ret;
    /* page alignment would be a bit better, but that's still fine compared to
     * copying */
    if (!((uintptr_t)buf & (SECTOR_SIZE-1)))
	return vbd_aligned_io(bs, sector_num, buf, nb_sectors, 0);
    iobuf = qemu_memalign(PAGE_SIZE, nb_sectors * SECTOR_SIZE);
    ret = vbd_aligned_io(bs, sector_num, iobuf, nb_sectors, 0);
    memcpy(buf, iobuf, nb_sectors * SECTOR_SIZE);
    free(iobuf);
    if (ret < 0)
	return ret;
    else if (ret != nb_sectors * SECTOR_SIZE)
	return -EINVAL;
    else
	return 0;
}

static int vbd_write(BlockDriverState *bs,
	int64_t sector_num, const uint8_t *buf, int nb_sectors)
{
    uint8_t *iobuf;
    int ret;
    if (!((uintptr_t)buf & (SECTOR_SIZE-1)))
	return vbd_aligned_io(bs, sector_num, (uint8_t*) buf, nb_sectors, 1);
    iobuf = qemu_memalign(PAGE_SIZE, nb_sectors * SECTOR_SIZE);
    memcpy(iobuf, buf, nb_sectors * SECTOR_SIZE);
    ret = vbd_aligned_io(bs, sector_num, iobuf, nb_sectors, 1);
    free(iobuf);
    if (ret < 0)
	return ret;
    else if (ret != nb_sectors * SECTOR_SIZE)
	return -EINVAL;
    else
	return 0;
}

static void vbd_aio_cancel(BlockDriverAIOCB *blockacb)
{
    /* TODO */
    //VbdAIOCB *acb = (VbdAIOCB *)blockacb;

    // Try to cancel. If can't, wait for it, drop the callback and call qemu_aio_release(acb)
}

static void vbd_nop_cb(void *opaque, int ret)
{
}

static BlockDriverAIOCB *vbd_aio_flush(BlockDriverState *bs,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    BDRVVbdState *s = bs->opaque;
    VbdAIOCB *acb = NULL;

    if (s->info.mode == O_RDONLY) {
        cb(opaque, 0);
        return NULL;
    }
    if (s->info.barrier == 1) {
        acb = vbd_aio_setup(bs, 0, NULL, 0,
                s->info.flush == 1 ? vbd_nop_cb : cb, opaque);
        if (!acb)
            return NULL;
        blkfront_aio_push_operation(&acb->aiocb, BLKIF_OP_WRITE_BARRIER);
    }
    if (s->info.flush == 1) {
        acb = vbd_aio_setup(bs, 0, NULL, 0, cb, opaque);
        if (!acb)
            return NULL;
        blkfront_aio_push_operation(&acb->aiocb, BLKIF_OP_FLUSH_DISKCACHE);
    }
    return &acb->common;
}

static void vbd_close(BlockDriverState *bs)
{
    BDRVVbdState *s = bs->opaque;
    bs->total_sectors = 0;
    if (s->fd >= 0) {
        qemu_set_fd_handler(s->fd, NULL, NULL, NULL);
        close(s->fd);
        s->fd = -1;
    }
    LIST_REMOVE(s, list);
}

static int64_t  vbd_getlength(BlockDriverState *bs)
{
    BDRVVbdState *s = bs->opaque;
    return s->info.sectors * s->info.sector_size;
}

static int vbd_flush(BlockDriverState *bs)
{
    BDRVVbdState *s = bs->opaque;
    blkfront_sync(s->dev);
    return 0;
}

/***********************************************/
/* host device */

static int vbd_is_inserted(BlockDriverState *bs)
{
    /* TODO: monitor the backend */
    return 1;
}

/* currently only used by fdc.c, but a CD version would be good too */
static int vbd_media_changed(BlockDriverState *bs)
{
    /* TODO: monitor the backend */
    return -ENOTSUP;
}

static int vbd_eject(BlockDriverState *bs, int eject_flag)
{
    /* TODO: Xen support needed */
    return -ENOTSUP;
}

static int vbd_set_locked(BlockDriverState *bs, int locked)
{
    /* TODO: Xen support needed */
    return -ENOTSUP;
}

BlockDriver bdrv_vbd = {
    "vbd",
    sizeof(BDRVVbdState),
    vbd_probe,
    vbd_open,
    NULL,
    NULL,
    vbd_close,
    NULL,
    vbd_flush,
    
    .bdrv_aio_read = vbd_aio_read,
    .bdrv_aio_write = vbd_aio_write,
    .bdrv_aio_cancel = vbd_aio_cancel,
    .bdrv_aio_flush = vbd_aio_flush,
    .aiocb_size = sizeof(VbdAIOCB),
    .bdrv_read = vbd_read,
    .bdrv_write = vbd_write,
    .bdrv_getlength = vbd_getlength,

    /* removable device support */
    .bdrv_is_inserted = vbd_is_inserted,
    .bdrv_media_changed = vbd_media_changed,
    .bdrv_eject = vbd_eject,
    .bdrv_set_locked = vbd_set_locked,
};

