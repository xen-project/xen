#include <linux/config.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include <linux/fs.h>
#include <linux/hdreg.h>                               /* HDIO_GETGEO, et al */
#include <linux/blkdev.h>
#include <linux/major.h>

/* NOTE: this is drive independent, so no inclusion of ide.h */

#include <asm/hypervisor-ifs/block.h>
#include <asm/hypervisor-ifs/hypervisor-if.h>
#include <asm/io.h>
#include <asm/uaccess.h>                                       /* put_user() */

#define MAJOR_NR XLBLK_MAJOR   /* force defns in blk.h, must preceed include */
static int xlblk_major = XLBLK_MAJOR;

#include <linux/blk.h>           /* must come after definition of MAJOR_NR!! */

/* instead of including linux/ide.h to pick up the definitiong of byte
 * (and consequently screwing up blk.h, we'll just copy the definition */
typedef unsigned char	byte; 

void xlblk_ide_register_disk(int, unsigned long);

#define XLBLK_MAX 2                                        /* very arbitrary */
#define XLBLK_MAJOR_NAME "blk"
#define IDE_PARTN_BITS 6                           /* from ide.h::PARTN_BITS */
#define IDE_PARTN_MASK ((1<<IDE_PARTN_BITS)-1)     /* from ide.h::PARTN_MASK */
static int xlblk_blk_size[XLBLK_MAX];
static int xlblk_blksize_size[XLBLK_MAX];
static int xlblk_hardsect_size[XLBLK_MAX];
static int xlblk_read_ahead[XLBLK_MAX];
static int xlblk_max_sectors[XLBLK_MAX];

#define XLBLK_RX_IRQ _EVENT_BLK_RX
#define XLBLK_TX_IRQ _EVENT_BLK_TX

typedef struct xlblk_device
{
  struct buffer_head *bh;
  unsigned int tx_count;                  /* number of used slots in tx ring */
} xlblk_device_t;

xlblk_device_t xlblk_device;

/* USE_REQUEST_QUEUE = 1  use (multiple) request queues
 *                   = 0  don't use IO request queue 
 */
#define USE_REQUEST_QUEUE 1

#define XLBLK_DEBUG       0
#define XLBLK_DEBUG_IOCTL 0

/* 
 * disk management
 */

xen_disk_info_t xen_disk_info;

/* some declarations */
void hypervisor_request(void *         id,
			int            operation,
			char *         buffer,
			unsigned long  block_number,
			unsigned short block_size,
			kdev_t         device,
			int            mode);


/* ------------------------------------------------------------------------
 */

static int xenolinux_block_open(struct inode *inode, struct file *filep)
{
  if (XLBLK_DEBUG) {
    printk (KERN_ALERT "xenolinux_block_open\n"); }
  return 0;
}

static int xenolinux_block_release(struct inode *inode, struct file *filep)
{
  if (XLBLK_DEBUG) {
    printk (KERN_ALERT "xenolinux_block_release\n"); }
  return 0;
}

static int xenolinux_block_ioctl(struct inode *inode, struct file *filep,
			  unsigned command, unsigned long argument)
{
  int minor_dev;

  if (XLBLK_DEBUG_IOCTL)
  {
    printk (KERN_ALERT "xenolinux_block_ioctl\n"); 
  }

  /* check permissions */
  if (!capable(CAP_SYS_ADMIN)) return -EPERM;
  if (!inode)                  return -EINVAL;
  minor_dev = MINOR(inode->i_rdev);
  if (minor_dev >= XLBLK_MAX)  return -ENODEV;

  if (XLBLK_DEBUG_IOCTL)
  {
    printk (KERN_ALERT  
	    "   command: 0x%x, argument: 0x%lx, minor: 0x%x\n",
	    command, (long) argument, minor_dev); 
  }
  
  switch (command)
  {
    case BLKGETSIZE :
    {
      if (XLBLK_DEBUG_IOCTL)
      {
	printk (KERN_ALERT
		"   BLKGETSIZE: %x %lx\n", BLKGETSIZE, 
		(long) xen_disk_info.disks[0].capacity); 
      }
      return put_user(xen_disk_info.disks[0].capacity, 
		      (unsigned long *) argument);
    }
    case BLKRRPART :
    {
      if (XLBLK_DEBUG_IOCTL) {
	printk (KERN_ALERT "   BLKRRPART: %x\n", BLKRRPART); }
      break;
    }
    case BLKSSZGET :
    {
      if (XLBLK_DEBUG_IOCTL) {
	printk (KERN_ALERT "   BLKSSZGET: %x 0x%x\n", BLKSSZGET,
		xlblk_hardsect_size[minor_dev]); }
      return xlblk_hardsect_size[minor_dev]; 
    }
    case HDIO_GETGEO :
    {
      struct hd_geometry *geo = (struct hd_geometry *)argument;

      if (XLBLK_DEBUG_IOCTL) {
	printk (KERN_ALERT "   HDIO_GETGEO: %x\n", HDIO_GETGEO); }

      if (!argument) return -EINVAL;
      /*
      if (put_user(0x80,  (byte *)&geo->heads)) return -EFAULT;
      if (put_user(0x3f,  (byte *)&geo->sectors)) return -EFAULT;
      if (put_user(0x20b, (unsigned short *) &geo->cylinders)) return -EFAULT;
      */
      if (put_user(0x00,  (unsigned long *) &geo->start)) return -EFAULT;
      if (put_user(0xff,  (byte *)&geo->heads)) return -EFAULT;
      if (put_user(0x3f,  (byte *)&geo->sectors)) return -EFAULT;
      if (put_user(0x106, (unsigned short *) &geo->cylinders)) return -EFAULT;

      return 0;
    }
    case HDIO_GETGEO_BIG :
    {
      struct hd_big_geometry *geo = (struct hd_big_geometry *) argument;

      if (XLBLK_DEBUG_IOCTL) {
	printk (KERN_ALERT "   HDIO_GETGEO_BIG: %x\n", HDIO_GETGEO_BIG); }

      if (!argument) return -EINVAL;
      /*
      if (put_user(0x80,  (byte *)&geo->heads))   return -EFAULT;
      if (put_user(0x3f,  (byte *)&geo->sectors)) return -EFAULT;
      if (put_user(0x20b, (unsigned int *) &geo->cylinders)) return -EFAULT;
      */
      if (put_user(0x00,  (unsigned long *) &geo->start))  return -EFAULT;
      if (put_user(0xff,  (byte *)&geo->heads))   return -EFAULT;
      if (put_user(0x3f,  (byte *)&geo->sectors)) return -EFAULT;
      if (put_user(0x106, (unsigned int *) &geo->cylinders)) return -EFAULT;

      return 0;
    }
    default :
    {
      if (XLBLK_DEBUG_IOCTL) {
	printk (KERN_ALERT "   eh? unknown ioctl\n"); }
      break;
    }
  }

  return 0;
}

static int xenolinux_block_check(kdev_t dev)
{
  if (XLBLK_DEBUG) {
    printk (KERN_ALERT "xenolinux_block_check\n"); }
  return 0;
}

static int xenolinux_block_revalidate(kdev_t dev)
{
  if (XLBLK_DEBUG) {
    printk (KERN_ALERT "xenolinux_block_revalidate\n"); }
  return 0;
}

/*
 * hypervisor_request
 *
 * request block io 
 * 
 * id: for guest use only.
 * operation: XEN_BLOCK_READ, XEN_BLOCK_WRITE or XEN_BLOCK_PROBE
 * buffer: buffer to read/write into. this should be a
 *   virtual address in the guest os.
 * block_number:  block to read
 * block_size:  size of each block
 * device:  ide/hda is 768 or 0x300
 * mode: XEN_BLOCK_SYNC or XEN_BLOCK_ASYNC.  async requests
 *   will queue until a sync request is issued.
 */

void hypervisor_request(void *         id,
			int            operation,
			char *         buffer,
			unsigned long  block_number,
			unsigned short block_size,
			kdev_t         device,
			int            mode)
{
  blk_ring_t *blk_ring = start_info.blk_ring;
  int position;
  void *buffer_pa, *buffer_ma; 
  kdev_t phys_device = (kdev_t) 0;
  unsigned long sector_number = 0;

#if 0
  printk(KERN_ALERT "[%x]", id); 
  printk (KERN_ALERT
	  "xlblk_req: id:%p op:%d, bf:%p, blk:%lu, sz:%u, dev:%x\n",
	  id, operation, buffer, block_number, block_size, device);
#endif

  /* XXX SMH: now need to convert guest virtual address to machine address */
  buffer_pa = (void *)virt_to_phys((unsigned long)buffer); 
  buffer_ma = (void *)phys_to_machine((unsigned long)buffer_pa); 

#if 0
  printk(KERN_ALERT "va %p => pa %p => ma %p\n", buffer, buffer_pa, buffer_ma);
#endif

  if (operation == XEN_BLOCK_PROBE)
  {
    phys_device = (kdev_t) 0;
    sector_number = 0;
  }
  else if (operation == XEN_BLOCK_READ || operation == XEN_BLOCK_WRITE)
  {
    /*
     * map logial major device to the physical device number 
     *
     *           XLBLK_MAJOR -> IDE0_MAJOR  (123 -> 3)
     */
    if (MAJOR(device) == XLBLK_MAJOR)
    {
      phys_device = MKDEV(IDE0_MAJOR, 0);
    }
    else
    {
      printk (KERN_ALERT
	      "error: xl_block::hypervisor_request: unknown device [0x%x]\n", 
	      device);
      BUG();
    }
  
    /*
     * compute real buffer location on disk
     * (from ll_rw_block.c::submit_bh)
     */
    {
      int idx = 0;

      struct gendisk *gd = (struct gendisk *) xen_disk_info.disks[idx].gendisk;
      unsigned int minor = MINOR(device);

      sector_number = block_number /* * block_size >> 9 */;

      if (gd != NULL)                     /* if we have a partition table... */
      {
	sector_number += gd->part[minor & IDE_PARTN_MASK].start_sect;
      }
    }
  }

  /*
   * CHECK TO SEE IF THERE IS SPACE IN THE RING
   */
  if (BLK_TX_RING_INC(blk_ring->tx_prod) == blk_ring->tx_cons)
  {
    printk (KERN_ALERT "hypervisor_request: tx_cons: %d, tx_prod:%d",
	    blk_ring->tx_cons, blk_ring->tx_prod);
  }

  /* fill out a communications ring structure 
     and then trap into the hypervisor */
  position = blk_ring->tx_prod;
  blk_ring->tx_ring[position].id            = id;
  blk_ring->tx_ring[position].priority      = mode;
  blk_ring->tx_ring[position].operation     = operation;
  blk_ring->tx_ring[position].buffer        = buffer_ma;
  blk_ring->tx_ring[position].block_number  = block_number;
  blk_ring->tx_ring[position].block_size    = block_size;
  blk_ring->tx_ring[position].device        = phys_device;
  blk_ring->tx_ring[position].sector_number = sector_number;

  blk_ring->tx_prod = BLK_TX_RING_INC(blk_ring->tx_prod);

  if (mode == XEN_BLOCK_SYNC)
  {
    /* trap into hypervisor */
    HYPERVISOR_block_io_op();
  }
  else if (mode == XEN_BLOCK_ASYNC)
  {
    /* for now, do nothing.  the request will go in the ring and
       the next sync request will trigger the hypervisor to act */
  }
  else
  {
    /* ummm, unknown mode. */
    BUG();
  }

  return;
}


/*
 * do_xlblk_request
 *
 * read a block; request is in a request queue
 *
 * TO DO: should probably release the io_request_lock and then re-acquire
 *        (see LDD p. 338)
 */

static void do_xlblk_request (request_queue_t *rq)
{
  struct request *req;

  if (XLBLK_DEBUG)
  {
    printk (KERN_ALERT "xlblk.c::do_xlblk_request for '%s'\n", DEVICE_NAME); 
  }

  while (!QUEUE_EMPTY)
  {
    struct buffer_head *bh;
    unsigned long offset;
    unsigned long length;
    int rw;

    req = CURRENT;

    if (XLBLK_DEBUG)
    {
      printk (KERN_ALERT
	      "do_xlblk_request %p: cmd %i, sec %lx, (%li) bh:%p\n",
	      req, req->cmd, req->sector,
	      req->current_nr_sectors, req->bh);
    }

    /* is there space in the tx ring for this request?
     * if the ring is full, then leave the request in the queue
     *
     * THIS IS A BIT BOGUS SINCE XEN COULD BE UPDATING TX_CONS
     * AT THE SAME TIME
     */
    {
      blk_ring_t *blk_ring = start_info.blk_ring;
      
      if (BLK_RX_RING_INC(blk_ring->tx_prod) == blk_ring->tx_cons)
      {
	printk (KERN_ALERT "OOPS, TX LOOKS FULL  cons: %d  prod: %d\n",
		blk_ring->tx_cons, blk_ring->tx_prod);
	break;
      }
    }

    req->errors = 0;
    blkdev_dequeue_request(req);

    bh = req->bh;

    while (bh)
    {

    offset = bh->b_rsector << 9;
    length = bh->b_size;
    
    rw = req->cmd;
    if (rw == READA)  rw= READ;
    if ((rw != READ) && (rw != WRITE))
    {
      printk (KERN_ALERT
	      "XenoLinux Virtual Block Device: bad command: %d\n", rw);
      BUG();
    }

    /*
    if (XLBLK_DEBUG)
    {
      printk (KERN_ALERT "xlblk.c::do_xlblk_request\n");
      printk (KERN_ALERT "  b_blocknr: 0x%lx %ld\n", 
                         bh->b_blocknr, bh->b_blocknr);
      printk (KERN_ALERT "  b_size:    0x%x  %d\n", bh->b_size, bh->b_size);
      printk (KERN_ALERT "  b_dev:     0x%x  %d\n", bh->b_dev, bh->b_dev);
      printk (KERN_ALERT "  b_rsector: 0x%lx %ld\n", 
                         bh->b_rsector, bh->b_rsector);
    }
    */

    hypervisor_request (req, rw == READ ? XEN_BLOCK_READ : XEN_BLOCK_WRITE, 
			bh->b_data, bh->b_rsector, bh->b_size, 
			bh->b_dev, XEN_BLOCK_SYNC);

      bh = bh->b_reqnext;
    }
  }

  return;
}

/*
 * xenolinux_block_request
 *
 * read a block without using a request queue
 */

static int xenolinux_block_request(request_queue_t *rq,
				   int rw,
				   struct buffer_head *bh)
{
  unsigned int minor;
  unsigned long offset;
  unsigned long length;

  if (XLBLK_DEBUG) {
    printk (KERN_ALERT "xlblk.c::xenolinux_block_request: %lx %d %lx\n",
	    (unsigned long) rq, rw, (unsigned long) bh); }
  /*
  printk (KERN_ALERT "xlblk.c::xlblk_request: op:%d bh:%p sect:%lu sz:%u\n",
	  rw,  bh, bh->b_rsector, bh->b_size);
  */

  minor = MINOR(bh->b_rdev);

  offset = bh->b_rsector << 9;
  length = bh->b_size;

  if (rw == READA)  rw= READ;
  if ((rw != READ) && (rw != WRITE))
  {
    printk (KERN_ALERT 
	    "XenoLinux Virtual Block Device: bad command: %d\n", rw);
    goto fail;
  }

  hypervisor_request (bh, rw == READ ? XEN_BLOCK_READ : XEN_BLOCK_WRITE, 
		      bh->b_data, bh->b_rsector, bh->b_size, 
		      bh->b_dev, XEN_BLOCK_SYNC);

  return 0;

 fail:
  return 0;
}

static struct block_device_operations xenolinux_block_fops = 
{
    open:               xenolinux_block_open,
    release:            xenolinux_block_release,
    ioctl:              xenolinux_block_ioctl,
    check_media_change: xenolinux_block_check,
    revalidate:         xenolinux_block_revalidate,
};

static void xlblk_rx_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
  xlblk_device_t *dev = (xlblk_device_t *)dev_id;
  blk_ring_t *blk_ring = start_info.blk_ring;
  struct buffer_head *bh;
  struct request *req;
  int loop;

  for (loop = blk_ring->rx_cons;
       loop != blk_ring->rx_prod;
       loop = BLK_RX_RING_INC(loop))
  {
    blk_ring_entry_t *bret = &blk_ring->rx_ring[loop];
    void *buffer_pa, *buffer_va; 

    buffer_pa = machine_to_phys((unsigned long)bret->buffer); 
    buffer_va = phys_to_virt((unsigned long)buffer_pa); 
    
#if 0
    printk(KERN_ALERT "xlblk_rx_int: buffer ma %p => pa %p => va %p\n", 
	   bret->buffer, buffer_pa, buffer_va); 


    if (XLBLK_DEBUG)
    {
      printk (KERN_ALERT 
	      "xlblock::xlblk_rx_int [%s]\n",
	      (bret->operation == XEN_BLOCK_READ) ? "read" : "write");
      printk (KERN_ALERT 
	      "   vbuf: %lx, pbuf: %lx, blockno: %lx, size: %x, device %x\n",
	      (unsigned long) buffer_va, (unsigned long) bret->buffer,
	      bret->block_number, bret->block_size, bret->device);
      printk (KERN_ALERT "   bret: %p  bh: %p\n", bret, bret->id); 
    }

    /*
    printk (KERN_ALERT
	    "xlblk_rx: id:%p op:%d, bf:%p, blk:%lu, sz:%u, dev:%x\n",
	    bret->id, bret->operation, bret->buffer, bret->block_number,
	    bret->block_size, bret->device);
    */
#endif

    if (USE_REQUEST_QUEUE)
    {
      req = (struct request *)bret->id;
      printk(KERN_ALERT "|%x|", req); 

      if (!end_that_request_first(req, 1, "NAME"))
      {
	blkdev_dequeue_request(req);

	/* should be end_that_request_last(req)
	   to wake up waiting processes (with complete) */
	blkdev_release_request(req);
      }

      /*
	if (XLBLK_DEBUG)
	{
	  int temp;
	  printk(KERN_ALERT 
		 "buff: 0x%p, blkno: 0x%lx, size: 0x%x, device 0x%x [%p]\n",
		 vbuffer, bret->block_number, bret->block_size, bret->device,
		 bh->b_end_io); 

	  for (temp = 0; temp < bret->block_size; temp++)
	  {
	    if (temp % 16 == 0)       printk ("[%4x]  ", temp);
	    else if (temp % 4 == 0)   printk (" ");
	                              printk ("%02x",
					      vbuffer[temp] & 255);
            if ((temp + 1) % 16 == 0) printk ("\n");
	  }
	  printk ("\n\n");
	}
      */

#ifdef BOGUS
      req = (struct request *)bret->id;
      while ((bh = req->bh) != NULL)
      {
	req->bh = bh->b_reqnext;
	bh->b_reqnext = NULL;
	bh->b_end_io(bh,1);
      }
      blkdev_release_request(req);
#endif /* BOGUS  */
    }
    else
    {
      bh = (struct buffer_head *)bret->id;
      bh->b_end_io(bh,1);

      /*
	if (XLBLK_DEBUG)
	{
	  int temp;
#if 0
	  printk(KERN_ALERT 
		 "buff: 0x%p, blkno: 0x%lx, size: 0x%x, device 0x%x [%p]\n",
		 vbuffer, bret->block_number, bret->block_size, bret->device,
		 bh->b_end_io); 
#endif

	  for (temp = 0; temp < bret->block_size; temp++)
	  {
	    if (temp % 16 == 0)       printk ("[%4x]  ", temp);
	    else if (temp % 4 == 0)   printk (" ");
	                              printk ("%02x",
					      vbuffer[temp] & 255);
            if ((temp + 1) % 16 == 0) printk ("\n");
	  }
	  printk ("\n\n");
	}
      */    
    }
  }

  blk_ring->rx_cons = loop;
}

static void xlblk_tx_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
  if (XLBLK_DEBUG) {
    printk (KERN_ALERT "--- xlblock::xlblk_tx_int\n"); }
}

int __init xlblk_init(void)
{
  blk_ring_t *blk_ring = start_info.blk_ring;
  int loop, error, result;

  /*
   * initialize memory rings to communicate with hypervisor 
   */

  if ( blk_ring == NULL ) return -ENOMEM;

  blk_ring->tx_prod = blk_ring->tx_cons = 0;
  blk_ring->rx_prod = blk_ring->rx_cons = 0;
  blk_ring->tx_ring = NULL;
  blk_ring->rx_ring = NULL;

  blk_ring->tx_ring = kmalloc(BLK_TX_RING_SIZE * sizeof(blk_ring_entry_t),
			      GFP_KERNEL);
  blk_ring->rx_ring = kmalloc(BLK_RX_RING_SIZE * sizeof(blk_ring_entry_t),
			      GFP_KERNEL);

  if ((blk_ring->tx_ring == NULL) ||
      (blk_ring->rx_ring == NULL))
  {
    printk (KERN_ALERT 
	    "error, could not allocate ring memory for block device\n");
    error = -ENOBUFS;
    goto fail;
  }

  /*
   * setup soft interrupts to communicate with hypervisor
   */

  error = request_irq(XLBLK_RX_IRQ, xlblk_rx_int, 0, "xlblk-rx", 
		      &xlblk_device);
  if (error)
  {
    printk(KERN_ALERT "Could not allocate receive interrupt\n");
    goto fail;
  }

  error = request_irq(XLBLK_TX_IRQ, xlblk_tx_int, 0, "xlblk-tx", 
		      &xlblk_device);
  if (error)
  {
    printk(KERN_ALERT "Could not allocate transmit interrupt\n");
    free_irq(XLBLK_RX_IRQ, &xlblk_device);
    goto fail;
  }

  /*
   * get information about physical drives
   *
   */
  {
    /* NOTE: this should only occur in domain 0 */
    memset (&xen_disk_info, 0, sizeof(xen_disk_info));
    xen_disk_info.count = 0;

    hypervisor_request(NULL, XEN_BLOCK_PROBE, (char *) &xen_disk_info,
		       0, 0, (kdev_t) 0, XEN_BLOCK_SYNC);

    {
      int loop;
      for (loop = 0; loop < xen_disk_info.count; loop++)
      {
	printk (KERN_ALERT "  %2d: type: %d, capacity: %ld\n",
		loop, xen_disk_info.disks[loop].type, 
		xen_disk_info.disks[loop].capacity);
      }
    }
  }

  /*
   * initialize device driver
   */

  SET_MODULE_OWNER(&xenolinux_block_fops);

  result = register_blkdev(xlblk_major, "block", &xenolinux_block_fops);
  if (result < 0)
  {
    printk (KERN_ALERT "xenolinux block: can't get major %d\n", xlblk_major);
    return result;
  }

  /* initialize global arrays in drivers/block/ll_rw_block.c */
  blk_size[xlblk_major] = xlblk_blk_size;
  blksize_size[xlblk_major] = xlblk_blksize_size;
  hardsect_size[xlblk_major] = xlblk_hardsect_size;
  read_ahead[xlblk_major] = xlblk_read_ahead;
  max_sectors[xlblk_major] = xlblk_max_sectors;
  for (loop = 0; loop < XLBLK_MAX; loop++)
  {
    xlblk_blk_size[loop] = xen_disk_info.disks[0].capacity;
    xlblk_blksize_size[loop] = 512;
    xlblk_hardsect_size[loop] = 512;
    xlblk_read_ahead[loop] = 8; 
    xlblk_max_sectors[loop] = 128;
  }

  if (USE_REQUEST_QUEUE)
  {
    /* NEED TO MODIFY THIS TO HANDLE MULTIPLE QUEUES
     * also, should replace do_xlblk_request with blk.h::DEVICE_REQUEST
     */
    blk_init_queue(BLK_DEFAULT_QUEUE(xlblk_major), do_xlblk_request);
    blk_queue_headactive(BLK_DEFAULT_QUEUE(xlblk_major), 0);
  }
  else
  {
    /* we don't use __make_request in ll_rw_blk */
    blk_queue_make_request(BLK_DEFAULT_QUEUE(xlblk_major), 
			   xenolinux_block_request);
  }
  xlblk_ide_register_disk(0, xen_disk_info.disks[0].capacity);

  /*
   * completion 
   */
  printk(KERN_ALERT 
	 "XenoLinux Virtual Block Device Driver installed [device: %d]\n",
	 xlblk_major);
  return 0;

 fail:
  if (blk_ring->tx_ring) kfree(blk_ring->tx_ring);
  if (blk_ring->rx_ring) kfree(blk_ring->rx_ring);
  return error;
}

void xlblk_ide_register_disk(int idx, unsigned long capacity)
{
  int units;
  int minors;
  struct gendisk *gd;

  /* plagarized from ide-probe.c::init_gendisk */

  units = 2;                                       /* from ide.h::MAX_DRIVES */

  minors    = units * (1<<IDE_PARTN_BITS);
  gd        = kmalloc (sizeof(struct gendisk), GFP_KERNEL);
  gd->sizes = kmalloc (minors * sizeof(int), GFP_KERNEL);
  gd->part  = kmalloc (minors * sizeof(struct hd_struct), GFP_KERNEL);
  memset(gd->part, 0, minors * sizeof(struct hd_struct));

  gd->major       = xlblk_major;                  /* our major device number */
  gd->major_name  = XLBLK_MAJOR_NAME;          /* treated special in genhd.c */
  gd->minor_shift = IDE_PARTN_BITS;               /* num bits for partitions */
  gd->max_p	  = 1<<IDE_PARTN_BITS;         /* 1 + max partitions / drive */
  gd->nr_real	  = units;                        /* current num real drives */
  gd->real_devices= NULL;                /* ptr to internal data (was: hwif) */
  gd->next	  = NULL;                       /* linked list of major devs */
  gd->fops        = &xenolinux_block_fops;                /* file operations */
  gd->de_arr      = kmalloc (sizeof *gd->de_arr * units, GFP_KERNEL);
  gd->flags	  = kmalloc (sizeof *gd->flags * units, GFP_KERNEL);
  if (gd->de_arr)   memset (gd->de_arr, 0, sizeof *gd->de_arr * units);
  if (gd->flags)    memset (gd->flags, 0, sizeof *gd->flags * units);
  add_gendisk(gd);

  xen_disk_info.disks[idx].gendisk = gd;

  /* default disk size is just a big number.  in the future, we
     need a message to probe the devices to determine the actual size */
  register_disk(gd, MKDEV(xlblk_major, 0), 1<<IDE_PARTN_BITS,
		&xenolinux_block_fops, capacity);

  return;
}

static void __exit xlblk_cleanup(void)
{
  /* CHANGE FOR MULTIQUEUE */
  blk_cleanup_queue(BLK_DEFAULT_QUEUE(xlblk_major));

  /* clean up global arrays */
  read_ahead[xlblk_major] = 0;
  if (blk_size[xlblk_major]) kfree(blk_size[xlblk_major]);
  blk_size[xlblk_major] = NULL;
  if (blksize_size[xlblk_major]) kfree(blksize_size[xlblk_major]);
  blksize_size[xlblk_major] = NULL;
  if (hardsect_size[xlblk_major]) kfree(hardsect_size[xlblk_major]);
  hardsect_size[xlblk_major] = NULL;

  /*
   *
   * TODO: FOR EACH GENDISK, FREE 
   *
   */

  if (unregister_blkdev(xlblk_major, "block"))
  {
    printk(KERN_ALERT
	   "XenoLinux Virtual Block Device Driver uninstalled with errors\n");
  }
  else
  {
    printk(KERN_ALERT "XenoLinux Virtual Block Device Driver uninstalled\n");
  }

  return;
}


#ifdef MODULE
module_init(xlblk_init);
module_exit(xlblk_cleanup);
#endif
