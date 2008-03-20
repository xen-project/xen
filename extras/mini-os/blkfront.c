/* Minimal block driver for Mini-OS. 
 * Copyright (c) 2007-2008 Samuel Thibault.
 * Based on netfront.c.
 */

#include <os.h>
#include <xenbus.h>
#include <events.h>
#include <errno.h>
#include <xen/io/blkif.h>
#include <gnttab.h>
#include <xmalloc.h>
#include <time.h>
#include <blkfront.h>
#include <lib.h>
#include <fcntl.h>

#ifndef HAVE_LIBC
#define strtoul simple_strtoul
#endif

/* Note: we generally don't need to disable IRQs since we hardly do anything in
 * the interrupt handler.  */

/* Note: we really suppose non-preemptive threads.  */

DECLARE_WAIT_QUEUE_HEAD(blkfront_queue);




#define BLK_RING_SIZE __RING_SIZE((struct blkif_sring *)0, PAGE_SIZE)
#define GRANT_INVALID_REF 0


struct blk_buffer {
    void* page;
    grant_ref_t gref;
};

struct blkfront_dev {
    domid_t dom;

    struct blkif_front_ring ring;
    grant_ref_t ring_ref;
    evtchn_port_t evtchn;
    blkif_vdev_t handle;

    char *nodename;
    char *backend;
    unsigned sector_size;
    unsigned sectors;
    int mode;
    int barrier;
    int flush;

#ifdef HAVE_LIBC
    int fd;
#endif
};

void blkfront_handler(evtchn_port_t port, struct pt_regs *regs, void *data)
{
#ifdef HAVE_LIBC
    struct blkfront_dev *dev = data;
    int fd = dev->fd;

    files[fd].read = 1;
#endif
    wake_up(&blkfront_queue);
}

struct blkfront_dev *init_blkfront(char *nodename, uint64_t *sectors, unsigned *sector_size, int *mode, int *info)
{
    xenbus_transaction_t xbt;
    char* err;
    char* message=NULL;
    struct blkif_sring *s;
    int retry=0;
    char* msg;
    char* c;

    struct blkfront_dev *dev;

    if (!nodename)
        nodename = "device/vbd/768";

    char path[strlen(nodename) + 1 + 10 + 1];

    printk("******************* BLKFRONT for %s **********\n\n\n", nodename);

    dev = malloc(sizeof(*dev));
    dev->nodename = strdup(nodename);

    snprintf(path, sizeof(path), "%s/backend-id", nodename);
    dev->dom = xenbus_read_integer(path); 
    evtchn_alloc_unbound(dev->dom, blkfront_handler, dev, &dev->evtchn);

    s = (struct blkif_sring*) alloc_page();
    memset(s,0,PAGE_SIZE);


    SHARED_RING_INIT(s);
    FRONT_RING_INIT(&dev->ring, s, PAGE_SIZE);

    dev->ring_ref = gnttab_grant_access(dev->dom,virt_to_mfn(s),0);

    // FIXME: proper frees on failures
again:
    err = xenbus_transaction_start(&xbt);
    if (err) {
        printk("starting transaction\n");
    }

    err = xenbus_printf(xbt, nodename, "ring-ref","%u",
                dev->ring_ref);
    if (err) {
        message = "writing ring-ref";
        goto abort_transaction;
    }
    err = xenbus_printf(xbt, nodename,
                "event-channel", "%u", dev->evtchn);
    if (err) {
        message = "writing event-channel";
        goto abort_transaction;
    }

    err = xenbus_printf(xbt, nodename, "state", "%u",
            4); /* connected */


    err = xenbus_transaction_end(xbt, 0, &retry);
    if (retry) {
            goto again;
        printk("completing transaction\n");
    }

    goto done;

abort_transaction:
    xenbus_transaction_end(xbt, 1, &retry);
    return NULL;

done:

    snprintf(path, sizeof(path), "%s/backend", nodename);
    msg = xenbus_read(XBT_NIL, path, &dev->backend);
    if (msg) {
        printk("Error %s when reading the backend path %s\n", msg, path);
        return NULL;
    }

    printk("backend at %s\n", dev->backend);

    dev->handle = strtoul(strrchr(nodename, '/')+1, NULL, 0);

    {
        char path[strlen(dev->backend) + 1 + 19 + 1];
        snprintf(path, sizeof(path), "%s/mode", dev->backend);
        msg = xenbus_read(XBT_NIL, path, &c);
        if (msg) {
            printk("Error %s when reading the mode\n", msg);
            return NULL;
        }
        if (*c == 'w')
            *mode = dev->mode = O_RDWR;
        else
            *mode = dev->mode = O_RDONLY;
        free(c);

        snprintf(path, sizeof(path), "%s/state", dev->backend);

        xenbus_watch_path(XBT_NIL, path);

        xenbus_wait_for_value(path,"4");

        xenbus_unwatch_path(XBT_NIL, path);

        snprintf(path, sizeof(path), "%s/info", dev->backend);
        *info = xenbus_read_integer(path);

        snprintf(path, sizeof(path), "%s/sectors", dev->backend);
        // FIXME: read_integer returns an int, so disk size limited to 1TB for now
        *sectors = dev->sectors = xenbus_read_integer(path);

        snprintf(path, sizeof(path), "%s/sector-size", dev->backend);
        *sector_size = dev->sector_size = xenbus_read_integer(path);

        snprintf(path, sizeof(path), "%s/feature-barrier", dev->backend);
        dev->barrier = xenbus_read_integer(path);

        snprintf(path, sizeof(path), "%s/feature-flush-cache", dev->backend);
        dev->flush = xenbus_read_integer(path);
    }
    unmask_evtchn(dev->evtchn);

    printk("%u sectors of %u bytes\n", dev->sectors, dev->sector_size);
    printk("**************************\n");

    return dev;
}

void shutdown_blkfront(struct blkfront_dev *dev)
{
    char* err;
    char *nodename = dev->nodename;

    char path[strlen(dev->backend) + 1 + 5 + 1];

    blkfront_sync(dev);

    printk("close blk: backend at %s\n",dev->backend);

    snprintf(path, sizeof(path), "%s/state", dev->backend);
    err = xenbus_printf(XBT_NIL, nodename, "state", "%u", 5); /* closing */
    xenbus_wait_for_value(path,"5");

    err = xenbus_printf(XBT_NIL, nodename, "state", "%u", 6);
    xenbus_wait_for_value(path,"6");

    unbind_evtchn(dev->evtchn);

    free(nodename);
    free(dev->backend);
    free(dev);
}

static void blkfront_wait_slot(struct blkfront_dev *dev)
{
    /* Wait for a slot */
    if (RING_FULL(&dev->ring)) {
	unsigned long flags;
	DEFINE_WAIT(w);
	local_irq_save(flags);
	while (1) {
	    blkfront_aio_poll(dev);
	    if (!RING_FULL(&dev->ring))
		break;
	    /* Really no slot, go to sleep. */
	    add_waiter(w, blkfront_queue);
	    local_irq_restore(flags);
	    schedule();
	    local_irq_save(flags);
	}
	remove_waiter(w);
	local_irq_restore(flags);
    }
}

/* Issue an aio */
void blkfront_aio(struct blkfront_aiocb *aiocbp, int write)
{
    struct blkfront_dev *dev = aiocbp->aio_dev;
    struct blkif_request *req;
    RING_IDX i;
    int notify;
    int n, j;
    uintptr_t start, end;

    // Can't io at non-sector-aligned location
    ASSERT(!(aiocbp->aio_offset & (dev->sector_size-1)));
    // Can't io non-sector-sized amounts
    ASSERT(!(aiocbp->aio_nbytes & (dev->sector_size-1)));
    // Can't io non-sector-aligned buffer
    ASSERT(!((uintptr_t) aiocbp->aio_buf & (dev->sector_size-1)));

    start = (uintptr_t)aiocbp->aio_buf & PAGE_MASK;
    end = ((uintptr_t)aiocbp->aio_buf + aiocbp->aio_nbytes + PAGE_SIZE - 1) & PAGE_MASK;
    aiocbp->n = n = (end - start) / PAGE_SIZE;

    /* qemu's IDE max multsect is 16 (8KB) and SCSI max DMA was set to 32KB,
     * so max 44KB can't happen */
    ASSERT(n <= BLKIF_MAX_SEGMENTS_PER_REQUEST);

    blkfront_wait_slot(dev);
    i = dev->ring.req_prod_pvt;
    req = RING_GET_REQUEST(&dev->ring, i);

    req->operation = write ? BLKIF_OP_WRITE : BLKIF_OP_READ;
    req->nr_segments = n;
    req->handle = dev->handle;
    req->id = (uintptr_t) aiocbp;
    req->sector_number = aiocbp->aio_offset / dev->sector_size;

    for (j = 0; j < n; j++) {
	uintptr_t data = start + j * PAGE_SIZE;
        if (!write) {
            /* Trigger CoW if needed */
            *(char*)data = 0;
            barrier();
        }
	aiocbp->gref[j] = req->seg[j].gref =
            gnttab_grant_access(dev->dom, virtual_to_mfn(data), write);
	req->seg[j].first_sect = 0;
	req->seg[j].last_sect = PAGE_SIZE / dev->sector_size - 1;
    }
    req->seg[0].first_sect = ((uintptr_t)aiocbp->aio_buf & ~PAGE_MASK) / dev->sector_size;
    req->seg[n-1].last_sect = (((uintptr_t)aiocbp->aio_buf + aiocbp->aio_nbytes - 1) & ~PAGE_MASK) / dev->sector_size;

    dev->ring.req_prod_pvt = i + 1;

    wmb();
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&dev->ring, notify);

    if(notify) notify_remote_via_evtchn(dev->evtchn);
}

void blkfront_aio_write(struct blkfront_aiocb *aiocbp)
{
    blkfront_aio(aiocbp, 1);
}

void blkfront_aio_read(struct blkfront_aiocb *aiocbp)
{
    blkfront_aio(aiocbp, 0);
}

int blkfront_aio_poll(struct blkfront_dev *dev)
{
    RING_IDX rp, cons;
    struct blkif_response *rsp;

moretodo:
#ifdef HAVE_LIBC
    files[dev->fd].read = 0;
    mb(); /* Make sure to let the handler set read to 1 before we start looking at the ring */
#endif

    rp = dev->ring.sring->rsp_prod;
    rmb(); /* Ensure we see queued responses up to 'rp'. */
    cons = dev->ring.rsp_cons;

    int nr_consumed = 0;
    while ((cons != rp))
    {
	rsp = RING_GET_RESPONSE(&dev->ring, cons);

        if (rsp->status != BLKIF_RSP_OKAY)
            printk("block error %d for op %d\n", rsp->status, rsp->operation);

        switch (rsp->operation) {
        case BLKIF_OP_READ:
        case BLKIF_OP_WRITE:
        {
            struct blkfront_aiocb *aiocbp = (void*) (uintptr_t) rsp->id;
            int j;

            for (j = 0; j < aiocbp->n; j++)
                gnttab_end_access(aiocbp->gref[j]);

            /* Nota: callback frees aiocbp itself */
            aiocbp->aio_cb(aiocbp, rsp->status ? -EIO : 0);
            break;
        }
        case BLKIF_OP_WRITE_BARRIER:
        case BLKIF_OP_FLUSH_DISKCACHE:
            break;
        default:
            printk("unrecognized block operation %d response\n", rsp->operation);
            break;
        }

	nr_consumed++;
	++cons;
    }
    dev->ring.rsp_cons = cons;

    int more;
    RING_FINAL_CHECK_FOR_RESPONSES(&dev->ring, more);
    if (more) goto moretodo;

    return nr_consumed;
}

static void blkfront_push_operation(struct blkfront_dev *dev, uint8_t op)
{
    int i;
    struct blkif_request *req;
    int notify;

    blkfront_wait_slot(dev);
    i = dev->ring.req_prod_pvt;
    req = RING_GET_REQUEST(&dev->ring, i);
    req->operation = op;
    req->nr_segments = 0;
    req->handle = dev->handle;
    /* Not used */
    req->id = 0;
    /* Not needed anyway, but the backend will check it */
    req->sector_number = 0;
    dev->ring.req_prod_pvt = i + 1;
    wmb();
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&dev->ring, notify);
    if (notify) notify_remote_via_evtchn(dev->evtchn);
}

void blkfront_sync(struct blkfront_dev *dev)
{
    unsigned long flags;

    if (dev->mode == O_RDWR) {
        if (dev->barrier == 1)
            blkfront_push_operation(dev, BLKIF_OP_WRITE_BARRIER);

        if (dev->flush == 1)
            blkfront_push_operation(dev, BLKIF_OP_FLUSH_DISKCACHE);
    }

    /* Note: This won't finish if another thread enqueues requests.  */
    local_irq_save(flags);
    DEFINE_WAIT(w);
    while (1) {
	blkfront_aio_poll(dev);
	if (RING_FREE_REQUESTS(&dev->ring) == RING_SIZE(&dev->ring))
	    break;

	add_waiter(w, blkfront_queue);
	local_irq_restore(flags);
	schedule();
	local_irq_save(flags);
    }
    remove_waiter(w);
    local_irq_restore(flags);
}

#ifdef HAVE_LIBC
int blkfront_open(struct blkfront_dev *dev)
{
    dev->fd = alloc_fd(FTYPE_BLK);
    printk("blk_open(%s) -> %d\n", dev->nodename, dev->fd);
    files[dev->fd].blk.dev = dev;
    return dev->fd;
}
#endif
