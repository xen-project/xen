/******************************************************************************
 * arch/xen/drivers/blkif/frontend/main.c
 * 
 * Xenolinux virtual block-device driver.
 * 
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 * Modifications by Mark A. Williamson are (c) Intel Research Cambridge
 */

#include "common.h"
#include <linux/blk.h>
#include <linux/cdrom.h>
#include <linux/tqueue.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <scsi/scsi.h>
#include <asm/ctrl_if.h>

typedef unsigned char byte; /* from linux/ide.h */

#define BLKIF_STATE_CLOSED       0
#define BLKIF_STATE_DISCONNECTED 1
#define BLKIF_STATE_CONNECTED    2
static unsigned int blkif_state = BLKIF_STATE_CLOSED;
static unsigned int blkif_evtchn, blkif_irq;

static int blkif_control_rsp_valid;
static blkif_response_t blkif_control_rsp;

static blkif_ring_t *blk_ring;
static BLK_RING_IDX resp_cons; /* Response consumer for comms ring. */
static BLK_RING_IDX req_prod;  /* Private request producer.         */

/* We plug the I/O ring if the driver is suspended or if the ring is full. */
#define RING_PLUGGED (((req_prod - resp_cons) == BLK_RING_SIZE) || \
                      (blkif_state != BLKIF_STATE_CONNECTED))


/*
 * Request queues with outstanding work, but ring is currently full.
 * We need no special lock here, as we always access this with the
 * io_request_lock held. We only need a small maximum list.
 */
#define MAX_PENDING 8
static request_queue_t *pending_queues[MAX_PENDING];
static int nr_pending;

static kdev_t        sg_dev;
static int           sg_operation = -1;
static unsigned long sg_next_sect;
#define DISABLE_SCATTERGATHER() (sg_operation = -1)

static inline void flush_requests(void)
{
    DISABLE_SCATTERGATHER();
    blk_ring->req_prod = req_prod;
    notify_via_evtchn(blkif_evtchn);
}


/*
 * blkif_update_int/update-vbds_task - handle VBD update events.
 *  Schedule a task for keventd to run, which will update the VBDs and perform 
 *  the corresponding updates to our view of VBD state.
 */
static struct tq_struct update_tq;
static void update_vbds_task(void *unused)
{ 
    xlvbd_update_vbds();
}


int blkif_open(struct inode *inode, struct file *filep)
{
    short xldev = inode->i_rdev; 
    struct gendisk *gd = get_gendisk(xldev);
    xl_disk_t *disk = xldev_to_xldisk(inode->i_rdev);
    short minor = MINOR(xldev); 

    if ( gd->part[minor].nr_sects == 0 )
    { 
        /*
         * Device either doesn't exist, or has zero capacity; we use a few
         * cheesy heuristics to return the relevant error code
         */
        if ( (gd->sizes[minor >> gd->minor_shift] != 0) ||
             ((minor & (gd->max_p - 1)) != 0) )
        { 
            /*
             * We have a real device, but no such partition, or we just have a
             * partition number so guess this is the problem.
             */
            return -ENXIO;     /* no such device or address */
        }
        else if ( gd->flags[minor >> gd->minor_shift] & GENHD_FL_REMOVABLE )
        {
            /* This is a removable device => assume that media is missing. */ 
            return -ENOMEDIUM; /* media not present (this is a guess) */
        } 
        else
        { 
            /* Just go for the general 'no such device' error. */
            return -ENODEV;    /* no such device */
        }
    }
    
    /* Update of usage count is protected by per-device semaphore. */
    disk->usage++;

    return 0;
}


int blkif_release(struct inode *inode, struct file *filep)
{
    xl_disk_t *disk = xldev_to_xldisk(inode->i_rdev);

    /*
     * When usage drops to zero it may allow more VBD updates to occur.
     * Update of usage count is protected by a per-device semaphore.
     */
    if ( --disk->usage == 0 )
    {
#if 0
        update_tq.routine = update_vbds_task;
        schedule_task(&update_tq);
#endif
    }

    return 0;
}


int blkif_ioctl(struct inode *inode, struct file *filep,
                          unsigned command, unsigned long argument)
{
    kdev_t dev = inode->i_rdev;
    struct hd_geometry *geo = (struct hd_geometry *)argument;
    struct gendisk *gd;     
    struct hd_struct *part; 
    int i;

    /* NB. No need to check permissions. That is done for us. */
    
    DPRINTK_IOCTL("command: 0x%x, argument: 0x%lx, dev: 0x%04x\n",
                  command, (long) argument, dev); 
  
    gd = get_gendisk(dev);
    part = &gd->part[MINOR(dev)]; 

    switch ( command )
    {
    case BLKGETSIZE:
        DPRINTK_IOCTL("   BLKGETSIZE: %x %lx\n", BLKGETSIZE, part->nr_sects); 
        return put_user(part->nr_sects, (unsigned long *) argument);

    case BLKGETSIZE64:
        DPRINTK_IOCTL("   BLKGETSIZE64: %x %llx\n", BLKGETSIZE64,
                      (u64)part->nr_sects * 512);
        return put_user((u64)part->nr_sects * 512, (u64 *) argument);

    case BLKRRPART:                               /* re-read partition table */
        DPRINTK_IOCTL("   BLKRRPART: %x\n", BLKRRPART);
        return blkif_revalidate(dev);

    case BLKSSZGET:
        return hardsect_size[MAJOR(dev)][MINOR(dev)]; 

    case BLKBSZGET:                                        /* get block size */
        DPRINTK_IOCTL("   BLKBSZGET: %x\n", BLKBSZGET);
        break;

    case BLKBSZSET:                                        /* set block size */
        DPRINTK_IOCTL("   BLKBSZSET: %x\n", BLKBSZSET);
        break;

    case BLKRASET:                                         /* set read-ahead */
        DPRINTK_IOCTL("   BLKRASET: %x\n", BLKRASET);
        break;

    case BLKRAGET:                                         /* get read-ahead */
        DPRINTK_IOCTL("   BLKRAFET: %x\n", BLKRAGET);
        break;

    case HDIO_GETGEO:
        /* note: these values are complete garbage */
        DPRINTK_IOCTL("   HDIO_GETGEO: %x\n", HDIO_GETGEO);
        if (!argument) return -EINVAL;
        if (put_user(0x00,  (unsigned long *) &geo->start)) return -EFAULT;
        if (put_user(0xff,  (byte *)&geo->heads)) return -EFAULT;
        if (put_user(0x3f,  (byte *)&geo->sectors)) return -EFAULT;
        if (put_user(0x106, (unsigned short *)&geo->cylinders)) return -EFAULT;
        return 0;

    case HDIO_GETGEO_BIG: 
        /* note: these values are complete garbage */
        DPRINTK_IOCTL("   HDIO_GETGEO_BIG: %x\n", HDIO_GETGEO_BIG);
        if (!argument) return -EINVAL;
        if (put_user(0x00,  (unsigned long *) &geo->start))  return -EFAULT;
        if (put_user(0xff,  (byte *)&geo->heads))   return -EFAULT;
        if (put_user(0x3f,  (byte *)&geo->sectors)) return -EFAULT;
        if (put_user(0x106, (unsigned int *) &geo->cylinders)) return -EFAULT;
        return 0;

    case CDROMMULTISESSION:
        DPRINTK("FIXME: support multisession CDs later\n");
        for ( i = 0; i < sizeof(struct cdrom_multisession); i++ )
            if ( put_user(0, (byte *)(argument + i)) ) return -EFAULT;
        return 0;

    case SCSI_IOCTL_GET_BUS_NUMBER:
        DPRINTK("FIXME: SCSI_IOCTL_GET_BUS_NUMBER ioctl in XL blkif");
        return -ENOSYS;

    default:
        printk(KERN_ALERT "ioctl %08x not supported by XL blkif\n", command);
        return -ENOSYS;
    }
    
    return 0;
}

/* check media change: should probably do something here in some cases :-) */
int blkif_check(kdev_t dev)
{
    DPRINTK("blkif_check\n");
    return 0;
}

int blkif_revalidate(kdev_t dev)
{
    struct block_device *bd;
    struct gendisk *gd;
    xl_disk_t *disk;
    unsigned long capacity;
    int i, rc = 0;
    
    if ( (bd = bdget(dev)) == NULL )
        return -EINVAL;

    /*
     * Update of partition info, and check of usage count, is protected
     * by the per-block-device semaphore.
     */
    down(&bd->bd_sem);

    if ( ((gd = get_gendisk(dev)) == NULL) ||
         ((disk = xldev_to_xldisk(dev)) == NULL) ||
         ((capacity = gd->part[MINOR(dev)].nr_sects) == 0) )
    {
        rc = -EINVAL;
        goto out;
    }

    if ( disk->usage > 1 )
    {
        rc = -EBUSY;
        goto out;
    }

    /* Only reread partition table if VBDs aren't mapped to partitions. */
    if ( !(gd->flags[MINOR(dev) >> gd->minor_shift] & GENHD_FL_VIRT_PARTNS) )
    {
        for ( i = gd->max_p - 1; i >= 0; i-- )
        {
            invalidate_device(dev+i, 1);
            gd->part[MINOR(dev+i)].start_sect = 0;
            gd->part[MINOR(dev+i)].nr_sects   = 0;
            gd->sizes[MINOR(dev+i)]           = 0;
        }

        grok_partitions(gd, MINOR(dev)>>gd->minor_shift, gd->max_p, capacity);
    }

 out:
    up(&bd->bd_sem);
    bdput(bd);
    return rc;
}


/*
 * blkif_queue_request
 *
 * request block io 
 * 
 * id: for guest use only.
 * operation: BLKIF_OP_{READ,WRITE,PROBE}
 * buffer: buffer to read/write into. this should be a
 *   virtual address in the guest os.
 */
static int blkif_queue_request(unsigned long   id,
                               int             operation,
                               char *          buffer,
                               unsigned long   sector_number,
                               unsigned short  nr_sectors,
                               kdev_t          device)
{
    unsigned long       buffer_ma = phys_to_machine(virt_to_phys(buffer)); 
    struct gendisk     *gd;
    blkif_request_t    *req;
    struct buffer_head *bh;
    unsigned int        fsect, lsect;

    fsect = (buffer_ma & ~PAGE_MASK) >> 9;
    lsect = fsect + nr_sectors - 1;

    /* Buffer must be sector-aligned. Extent mustn't cross a page boundary. */
    if ( unlikely((buffer_ma & ((1<<9)-1)) != 0) )
        BUG();
    if ( lsect > 7 )
        BUG();

    buffer_ma &= PAGE_MASK;

    if ( unlikely(blkif_state != BLKIF_STATE_CONNECTED) )
        return 1;

    switch ( operation )
    {

    case BLKIF_OP_READ:
    case BLKIF_OP_WRITE:
        gd = get_gendisk(device); 

        /*
         * Update the sector_number we'll pass down as appropriate; note that
         * we could sanity check that resulting sector will be in this
         * partition, but this will happen in driver backend anyhow.
         */
        sector_number += gd->part[MINOR(device)].start_sect;

        /*
         * If this unit doesn't consist of virtual partitions then we clear 
         * the partn bits from the device number.
         */
        if ( !(gd->flags[MINOR(device)>>gd->minor_shift] & 
               GENHD_FL_VIRT_PARTNS) )
            device &= ~(gd->max_p - 1);

        if ( (sg_operation == operation) &&
             (sg_dev == device) &&
             (sg_next_sect == sector_number) )
        {
            req = &blk_ring->ring[MASK_BLK_IDX(req_prod-1)].req;
            bh = (struct buffer_head *)id;
            bh->b_reqnext = (struct buffer_head *)req->id;
            req->id = id;
            req->frame_and_sects[req->nr_segments] = 
                buffer_ma | (fsect<<3) | lsect;
            if ( ++req->nr_segments < BLKIF_MAX_SEGMENTS_PER_REQUEST )
                sg_next_sect += nr_sectors;
            else
                DISABLE_SCATTERGATHER();
            return 0;
        }
        else if ( RING_PLUGGED )
        {
            return 1;
        }
        else
        {
            sg_operation = operation;
            sg_dev       = device;
            sg_next_sect = sector_number + nr_sectors;
        }
        break;

    default:
        panic("unknown op %d\n", operation);
    }

    /* Fill out a communications ring structure. */
    req = &blk_ring->ring[MASK_BLK_IDX(req_prod)].req;
    req->id            = id;
    req->operation     = operation;
    req->sector_number = (blkif_sector_t)sector_number;
    req->device        = device; 
    req->nr_segments   = 1;
    req->frame_and_sects[0] = buffer_ma | (fsect<<3) | lsect;
    req_prod++;

    return 0;
}


/*
 * do_blkif_request
 *  read a block; request is in a request queue
 */
void do_blkif_request(request_queue_t *rq)
{
    struct request *req;
    struct buffer_head *bh, *next_bh;
    int rw, nsect, full, queued = 0;

    DPRINTK("Entered do_blkif_request\n"); 

    while ( !rq->plugged && !list_empty(&rq->queue_head))
    {
        if ( (req = blkdev_entry_next_request(&rq->queue_head)) == NULL ) 
            goto out;
  
        DPRINTK("do_blkif_request %p: cmd %i, sec %lx, (%li/%li) bh:%p\n",
                req, req->cmd, req->sector,
                req->current_nr_sectors, req->nr_sectors, req->bh);

        rw = req->cmd;
        if ( rw == READA )
            rw = READ;
        if ( unlikely((rw != READ) && (rw != WRITE)) )
            panic("XenoLinux Virtual Block Device: bad cmd: %d\n", rw);

        req->errors = 0;

        bh = req->bh;
        while ( bh != NULL )
        {
            next_bh = bh->b_reqnext;
            bh->b_reqnext = NULL;

            full = blkif_queue_request(
                (unsigned long)bh,
                (rw == READ) ? BLKIF_OP_READ : BLKIF_OP_WRITE, 
                bh->b_data, bh->b_rsector, bh->b_size>>9, bh->b_rdev);

            if ( full )
            { 
                bh->b_reqnext = next_bh;
                pending_queues[nr_pending++] = rq;
                if ( unlikely(nr_pending >= MAX_PENDING) )
                    BUG();
                goto out; 
            }

            queued++;

            /* Dequeue the buffer head from the request. */
            nsect = bh->b_size >> 9;
            bh = req->bh = next_bh;
            
            if ( bh != NULL )
            {
                /* There's another buffer head to do. Update the request. */
                req->hard_sector += nsect;
                req->hard_nr_sectors -= nsect;
                req->sector = req->hard_sector;
                req->nr_sectors = req->hard_nr_sectors;
                req->current_nr_sectors = bh->b_size >> 9;
                req->buffer = bh->b_data;
            }
            else
            {
                /* That was the last buffer head. Finalise the request. */
                if ( unlikely(end_that_request_first(req, 1, "XenBlk")) )
                    BUG();
                blkdev_dequeue_request(req);
                end_that_request_last(req);
            }
        }
    }

 out:
    if ( queued != 0 )
        flush_requests();
}


static void kick_pending_request_queues(void)
{
    /* We kick pending request queues if the ring is reasonably empty. */
    if ( (nr_pending != 0) && 
         ((req_prod - resp_cons) < (BLK_RING_SIZE >> 1)) )
    {
        /* Attempt to drain the queue, but bail if the ring becomes full. */
        while ( (nr_pending != 0) && !RING_PLUGGED )
            do_blkif_request(pending_queues[--nr_pending]);
    }
}


static void blkif_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
    BLK_RING_IDX i; 
    unsigned long flags; 
    struct buffer_head *bh, *next_bh;
    
    if ( unlikely(blkif_state == BLKIF_STATE_CLOSED) )
        return;
    
    spin_lock_irqsave(&io_request_lock, flags);     

    for ( i = resp_cons; i != blk_ring->resp_prod; i++ )
    {
        blkif_response_t *bret = &blk_ring->ring[MASK_BLK_IDX(i)].resp;
        switch ( bret->operation )
        {
        case BLKIF_OP_READ:
        case BLKIF_OP_WRITE:
            if ( unlikely(bret->status != BLKIF_RSP_OKAY) )
                DPRINTK("Bad return from blkdev data request: %lx\n",
                        bret->status);
            for ( bh = (struct buffer_head *)bret->id; 
                  bh != NULL; 
                  bh = next_bh )
            {
                next_bh = bh->b_reqnext;
                bh->b_reqnext = NULL;
                bh->b_end_io(bh, bret->status == BLKIF_RSP_OKAY);
            }
            break;
        case BLKIF_OP_PROBE:
            memcpy(&blkif_control_rsp, bret, sizeof(*bret));
            blkif_control_rsp_valid = 1;
            break;
        default:
            BUG();
        }
    }
    
    resp_cons = i;

    kick_pending_request_queues();

    spin_unlock_irqrestore(&io_request_lock, flags);
}


void blkif_control_send(blkif_request_t *req, blkif_response_t *rsp)
{
    unsigned long flags;

 retry:
    while ( (req_prod - resp_cons) == BLK_RING_SIZE )
    {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(1);
    }

    spin_lock_irqsave(&io_request_lock, flags);
    if ( (req_prod - resp_cons) == BLK_RING_SIZE )
    {
        spin_unlock_irqrestore(&io_request_lock, flags);
        goto retry;
    }

    DISABLE_SCATTERGATHER();
    memcpy(&blk_ring->ring[MASK_BLK_IDX(req_prod)].req, req, sizeof(*req));
    req_prod++;
    flush_requests();

    spin_unlock_irqrestore(&io_request_lock, flags);

    while ( !blkif_control_rsp_valid )
    {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(1);
    }

    memcpy(rsp, &blkif_control_rsp, sizeof(*rsp));
    blkif_control_rsp_valid = 0;
}


static void blkif_status_change(blkif_fe_interface_status_changed_t *status)
{
    ctrl_msg_t                   cmsg;
    blkif_fe_interface_connect_t up;

    if ( status->handle != 0 )
    {
        printk(KERN_WARNING "Status change on unsupported blkif %d\n",
               status->handle);
        return;
    }

    switch ( status->status )
    {
    case BLKIF_INTERFACE_STATUS_DESTROYED:
        printk(KERN_WARNING "Unexpected blkif-DESTROYED message in state %d\n",
               blkif_state);
        break;

    case BLKIF_INTERFACE_STATUS_DISCONNECTED:
        if ( blkif_state != BLKIF_STATE_CLOSED )
        {
            printk(KERN_WARNING "Unexpected blkif-DISCONNECTED message"
                   " in state %d\n", blkif_state);
            break;
        }

        /* Move from CLOSED to DISCONNECTED state. */
        blk_ring = (blkif_ring_t *)__get_free_page(GFP_KERNEL);
        blk_ring->req_prod = blk_ring->resp_prod = resp_cons = req_prod = 0;
        blkif_state  = BLKIF_STATE_DISCONNECTED;

        /* Construct an interface-CONNECT message for the domain controller. */
        cmsg.type      = CMSG_BLKIF_FE;
        cmsg.subtype   = CMSG_BLKIF_FE_INTERFACE_CONNECT;
        cmsg.length    = sizeof(blkif_fe_interface_connect_t);
        up.handle      = 0;
        up.shmem_frame = virt_to_machine(blk_ring) >> PAGE_SHIFT;
        memcpy(cmsg.msg, &up, sizeof(up));
        
        /* Tell the controller to bring up the interface. */
        ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
        break;

    case BLKIF_INTERFACE_STATUS_CONNECTED:
        if ( blkif_state == BLKIF_STATE_CLOSED )
        {
            printk(KERN_WARNING "Unexpected blkif-CONNECTED message"
                   " in state %d\n", blkif_state);
            break;
        }

        blkif_evtchn = status->evtchn;
        blkif_irq = bind_evtchn_to_irq(blkif_evtchn);
        (void)request_irq(blkif_irq, blkif_int, 0, "blkif", NULL);
        
        /* Probe for discs that are attached to the interface. */
        xlvbd_init();
        
        blkif_state = BLKIF_STATE_CONNECTED;
        
        /* Kick pending requests. */
        spin_lock_irq(&io_request_lock);
        kick_pending_request_queues();
        spin_unlock_irq(&io_request_lock);
        break;

    default:
        printk(KERN_WARNING "Status change to unknown value %d\n", 
               status->status);
        break;
    }
}


static void blkif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    switch ( msg->subtype )
    {
    case CMSG_BLKIF_FE_INTERFACE_STATUS_CHANGED:
        if ( msg->length != sizeof(blkif_fe_interface_status_changed_t) )
            goto parse_error;
        blkif_status_change((blkif_fe_interface_status_changed_t *)
                            &msg->msg[0]);
        break;        
#if 0
    case CMSG_BLKIF_FE_VBD_STATUS_CHANGED:
        update_tq.routine = update_vbds_task;
        schedule_task(&update_tq);
        break;
#endif
    default:
        goto parse_error;
    }

    ctrl_if_send_response(msg);
    return;

 parse_error:
    msg->length = 0;
    ctrl_if_send_response(msg);
}


int __init xlblk_init(void)
{
    ctrl_msg_t                       cmsg;
    blkif_fe_driver_status_changed_t st;

    if ( start_info.flags & SIF_INITDOMAIN )
        return 0;

    (void)ctrl_if_register_receiver(CMSG_BLKIF_FE, blkif_ctrlif_rx,
                                    CALLBACK_IN_BLOCKING_CONTEXT);

    /* Send a driver-UP notification to the domain controller. */
    cmsg.type      = CMSG_BLKIF_FE;
    cmsg.subtype   = CMSG_BLKIF_FE_DRIVER_STATUS_CHANGED;
    cmsg.length    = sizeof(blkif_fe_driver_status_changed_t);
    st.status      = BLKIF_DRIVER_STATUS_UP;
    memcpy(cmsg.msg, &st, sizeof(st));
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);

    /*
     * We should read 'nr_interfaces' from response message and wait
     * for notifications before proceeding. For now we assume that we
     * will be notified of exactly one interface.
     */
    while ( blkif_state != BLKIF_STATE_CONNECTED )
    {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(1);
    }

    return 0;
}


static void __exit xlblk_cleanup(void)
{
    /* XXX FIXME */
    BUG();
}


#ifdef MODULE
module_init(xlblk_init);
module_exit(xlblk_cleanup);
#endif


void blkdev_suspend(void)
{
    /* XXX FIXME */
    BUG();
}


void blkdev_resume(void)
{
    /* XXX FIXME */
    BUG();
}
