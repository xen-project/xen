/*
 * xen-block.c
 *
 * process incoming block io requests from guestos's.
 */

#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <xeno/sched.h>
#include <xeno/blkdev.h>
#include <xeno/event.h>                                    /* mark_hyp_event */
#include <hypervisor-ifs/block.h>
#include <hypervisor-ifs/hypervisor-if.h>
#include <asm-i386/io.h>
#include <asm/spinlock.h>

#define XEN_BLK_DEBUG 0
#define XEN_BLK_DEBUG_LEVEL KERN_ALERT

#define XEN_BLK_REQUEST_LIST_SIZE 256                      /* very arbitrary */

typedef struct blk_request
{
  struct list_head queue;
  struct buffer_head *bh;
  blk_ring_entry_t request;
  struct task_struct *domain;                           /* requesting domain */
} blk_request_t;

static int pending_work;                  /* which domains have work for us? */
blk_request_t blk_request_list[XEN_BLK_REQUEST_LIST_SIZE];
struct list_head free_queue;                              /* unused requests */
struct list_head pending_queue;                      /* waiting for hardware */
struct list_head io_done_queue;       /* request completed. send to guest os */
spinlock_t free_queue_lock;
spinlock_t pending_queue_lock;
spinlock_t io_done_queue_lock;

/* some definitions */
void dumpx (char *buffer, int count);
void printx (char * string);
long do_block_io_op_domain (struct task_struct* task);
int dispatch_rw_block_io (int index);
int dispatch_probe_block_io (int index);
int dispatch_debug_block_io (int index);

/*
 * end_block_io_op
 *
 * IO has completed.  Need to notify the guest operating system.
 * Called from hardware interrupt.
 */

void end_block_io_op(struct buffer_head * bh)
{
  unsigned long cpu_mask;
  /* struct list_head *list;*/
  blk_request_t *blk_request = NULL;
  unsigned long flags;                                           /* irq save */

#if 0
  printk("{E}"); 
#endif
  if (XEN_BLK_DEBUG)  printk(XEN_BLK_DEBUG_LEVEL
			     "XEN end_block_io_op,  bh: %lx\n",
			     (unsigned long)bh);

  {
    char temp[100];
    sprintf(temp, "endio  bh: 0x%p, blkno: 0x%lx",
	    bh, bh->b_blocknr);
    printx(temp);
  }

  spin_lock_irqsave(&pending_queue_lock, flags);
  /*
  list_for_each (list, &pending_queue)
  {
    blk_request = list_entry(list, blk_request_t, queue);
    if (blk_request->bh == bh)      
    {
      break;
    }
  }
  */
  blk_request = (blk_request_t *)bh->b_xen_request;
  if (blk_request == NULL)
  {
    printk (KERN_ALERT
	    "   block io interrupt received for unknown buffer [0x%lx]\n",
	    (unsigned long) bh);
    spin_unlock_irqrestore(&pending_queue_lock, flags);
    return;
  }
  list_del(&blk_request->queue);
  spin_unlock_irqrestore(&pending_queue_lock, flags);

  spin_lock_irqsave(&io_done_queue_lock, flags);
  list_add_tail(&blk_request->queue, &io_done_queue);
  spin_unlock_irqrestore(&io_done_queue_lock, flags);

  /* enqueue work */
  cpu_mask = mark_hyp_event(blk_request->domain, _HYP_EVENT_BLK_RX);

  return;
}

/*
 * flush_blk_queue
 *
 * Called by the hypervisor synchronously when there is something to do
 * (block transfers have completed)
 */

void flush_blk_queue(void)
{
  blk_request_t *blk_request;
  int position = 0;
  blk_ring_t *blk_ring;
  unsigned long flags;
  int loop;

#if 0
  printk("{F}"); 
#endif
  /*
  if (XEN_BLK_DEBUG)  printk(XEN_BLK_DEBUG_LEVEL
			     "XEN flush_blk_queue\n");
  */

  clear_bit(_HYP_EVENT_BLK_RX, &current->hyp_events);

  /* NEED LOCK? */
  spin_lock_irqsave(&io_done_queue_lock, flags);
  while (!list_empty(&io_done_queue))
  {
    blk_request = list_entry(io_done_queue.next, blk_request_t, queue);
    list_del (&blk_request->queue);
    spin_unlock_irqrestore(&io_done_queue_lock, flags);

    /* place on ring for guest os */ 
    blk_ring = blk_request->domain->blk_ring_base;
    position = blk_ring->rx_prod;

    if (XEN_BLK_DEBUG)  printk(XEN_BLK_DEBUG_LEVEL
			       "XEN flush_blk_queue [%d]\n", position);

    memcpy(&blk_ring->rx_ring[position], &blk_request->request,
	   sizeof(blk_ring_entry_t));
    blk_ring->rx_prod = BLK_RX_RING_INC(blk_ring->rx_prod);

    /* notify appropriate guest os */
    set_bit(_EVENT_BLK_RX,
	    &blk_request->domain->shared_info->events);

    if (0)
    {
      int temp;
      struct buffer_head *bh = blk_request->bh;
      char * vbuffer = bh->b_data;

      printk (KERN_ALERT "XEN return block 0x%lx\n", bh->b_blocknr);

      for (temp = 0; temp < bh->b_size; temp++)
      {
	if (temp % 16 == 0)       printk ("[%04x]  ", temp);
	else if (temp % 4 == 0)   printk (" ");
	                          printk ("%02x",
					  vbuffer[temp] & 255);
	if ((temp + 1) % 16 == 0) printk ("\n");
      }
      printk ("\n\n");
    }

    /* free the buffer header allocated in do_block_io_op */
    if (blk_request->bh)
    {
      kfree(blk_request->bh);                     /* alloc in do_block_io_op */
    }

    spin_lock_irqsave(&free_queue_lock, flags);
    list_add_tail(&blk_request->queue, &free_queue);
    spin_unlock_irqrestore(&free_queue_lock, flags);

    spin_lock_irqsave(&io_done_queue_lock, flags);
  }
  spin_unlock_irqrestore(&io_done_queue_lock, flags);

  /*
   * now check if there is any pending work from any domain
   * that we were previously unable to process.
   *
   * NOTE: the current algorithm will check _every_ domain
   * and wake up _every_ domain that has pending work.
   * In the future, we should stop waking up domains once
   * there isn't any space for their requests any more
   * ALSO, we need to maintain a counter of the last domain
   * that we woke up for fairness... we shouldn't restart
   * at domain 0 every time (although we might want to special
   * case domain 0);
   */
  for (loop = 0; loop < XEN_BLOCK_MAX_DOMAINS; loop++)
  {
    int domain = pending_work & (1 << loop);

    if (domain)
    {
      struct task_struct *mytask = current;

      /*
      printk (KERN_ALERT 
	      "flush_blk_queue  pending_work: %x  domain: %d  loop: %d\n",
	      pending_work, domain, loop);
      */
      /* IS THERE A BETTER WAY OF FINDING THE TASK STRUCT FOR A 
       * PARTICULAR DOMAIN? 
       *
       * WHAT IF THE TASK GOES AWAY BEFORE WE HAVE A CHANCE TO
       * FINISH PROCESSING ALL OF ITS REQUESTS?
       */
      while (mytask->domain != loop)
      {
	mytask = mytask->next_task;
      }
      do_block_io_op_domain(mytask);

      pending_work = pending_work & !(1 << loop);
      /*
      printk (KERN_ALERT 
	      "                 pending_work: %x  domain: %d  loop: %d\n",
	      pending_work, domain, loop);
      */
    }
  }
}

/*
 * do_block_io_op
 *
 * Accept a block io request from a guest operating system.
 * There is an entry in the hypervisor_call_table (xen/arch/i386/entry.S).
 */

long do_block_io_op (void)
{
  return do_block_io_op_domain(current);
}

/*
 * do_block_io_op
 *
 * handle the requests for a particular domain
 */

long do_block_io_op_domain (struct task_struct* task)
{
  blk_ring_t *blk_ring = task->blk_ring_base;
  int loop;

#if 0
  printk("{%d}", current->domain); 
#endif
  if (XEN_BLK_DEBUG)  printk(XEN_BLK_DEBUG_LEVEL
			     "XEN do_block_io_op %d %d\n",
			     blk_ring->tx_cons, blk_ring->tx_prod);

  for (loop = blk_ring->tx_cons;
       loop != blk_ring->tx_prod;
       loop = BLK_TX_RING_INC(loop))
  {
    int status = 1;

    switch (blk_ring->tx_ring[loop].operation)
    {
      case XEN_BLOCK_READ :
      case XEN_BLOCK_WRITE :
      {
	status = dispatch_rw_block_io(loop);
	break;
      }
      case XEN_BLOCK_PROBE :
      {
	status = dispatch_probe_block_io(loop);
	break;
      }
      case XEN_BLOCK_DEBUG :
      {
	status = dispatch_debug_block_io(loop);
	break;
      }
      default :
      {
	printk (KERN_ALERT "error: unknown block io operation [%d]\n",
		blk_ring->tx_ring[loop].operation);
	BUG();
      }
    }

    if (status)
    {
      /* unable to successfully issue / complete command, maybe because
       * another resource (e.g. disk request buffers) is unavailable.
       * stop removing items from the communications ring and try 
       * again later 
       */

      /*
      printk ("do_block_io_op_domain  domain:%d, pending_work: %x\n",
	      task->domain, pending_work);
      */
      pending_work = pending_work | (1 << task->domain);
      /*
      printk ("do_block_io_op_domain  domain:%d, pending_work: %x\n",
	      task->domain, pending_work);
      */
      break;
    }
  }

  blk_ring->tx_cons = loop;

  return 0L;
}

int dispatch_debug_block_io (int index)
{
  struct task_struct *task;
  blk_ring_t *blk_ring = current->blk_ring_base;
  char * buffer;
  char output[1000];

  int foobar = (unsigned long)blk_ring->tx_ring[index].block_number;

  printk (KERN_ALERT "dispatch_debug_block_io %d\n", foobar);

  buffer = phys_to_virt(blk_ring->tx_ring[index].buffer);
  strcpy (buffer, "DEBUG\n");

  task = current;
  sprintf (buffer, "current %d\n", current->domain);
  sprintf (buffer, "%s  tx: prod: %d, cons: %d, size: %d\n", buffer,
	   blk_ring->tx_prod, blk_ring->tx_cons, blk_ring->tx_ring_size);
  sprintf (buffer, "%s  rx: prod: %d, cons: %d, size: %d\n", buffer,
	   blk_ring->rx_prod, blk_ring->rx_cons, blk_ring->rx_ring_size);

  task = task->next_task;
  while (task != current)
  {
    blk_ring = task->blk_ring_base;
    sprintf (buffer, "%stask %d\n", buffer, task->domain);
    if (blk_ring != NULL)
    {
      sprintf (buffer, "%s  tx: prod: %d, cons: %d, size: %d\n",
	       buffer, blk_ring->tx_prod, blk_ring->tx_cons, 
	       blk_ring->tx_ring_size);
      sprintf (buffer, "%s  rx: prod: %d, cons: %d, size: %d\n",
	       buffer, blk_ring->rx_prod, blk_ring->rx_cons, 
	       blk_ring->rx_ring_size);
    }
    task = task->next_task;
  }
  dumpx(output, foobar);
  sprintf (buffer, "%s%s\n", buffer, output);

  return 0;
}

int dispatch_probe_block_io (int index)
{
  blk_ring_t *blk_ring = current->blk_ring_base;
  xen_disk_info_t *xdi;

  xdi = phys_to_virt(blk_ring->tx_ring[index].buffer);

  ide_probe_devices(xdi);

  return 0;
}

int dispatch_rw_block_io (int index)
{
  blk_ring_t *blk_ring = current->blk_ring_base;
  struct buffer_head *bh;
  struct request_queue *rq;
  int operation;
  blk_request_t *blk_request;
  unsigned long flags;

    /*
     * check to make sure that the block request seems at least
     * a bit legitimate
     */
    if ((blk_ring->tx_ring[index].block_size & (0x200 - 1)) != 0)
    {
      printk(KERN_ALERT
	     "    error: dodgy block size: %d\n", 
	     blk_ring->tx_ring[index].block_size);
      BUG();
    }

    if (XEN_BLK_DEBUG) 
    {
    printk(XEN_BLK_DEBUG_LEVEL
	   "    tx_cons: %d  tx_prod %d  index: %d     op: %s, pri: %s\n",
	   blk_ring->tx_cons, blk_ring->tx_prod, index,
	   (blk_ring->tx_ring[index].operation == XEN_BLOCK_READ ? "read" : "write"),
	   (blk_ring->tx_ring[index].priority == XEN_BLOCK_SYNC ? "sync" : "async"));
    }

    {
      char temp[100];
      sprintf(temp, "issue  buf: 0x%p, bh: 0x%p, blkno: 0x%lx",
	      blk_ring->tx_ring[index].buffer, bh,
	      (unsigned long)blk_ring->tx_ring[index].block_number);
      printx(temp);
    }

    /* find an empty request slot */
    spin_lock_irqsave(&free_queue_lock, flags);
    if (list_empty(&free_queue))
    {
      /*      printk (KERN_ALERT "dispatch_rw_block_io EMPTY FREE LIST!! %d\n", index); */
      spin_unlock_irqrestore(&free_queue_lock, flags);
      return 1;
    }
    blk_request = list_entry(free_queue.next, blk_request_t, queue);
    list_del(&blk_request->queue);
    spin_unlock_irqrestore(&free_queue_lock, flags);

    /* place request on pending list */
    spin_lock_irqsave(&pending_queue_lock, flags);
    list_add_tail(&blk_request->queue, &pending_queue);
    spin_unlock_irqrestore(&pending_queue_lock, flags);

    /* we'll be doing this frequently, would a cache be appropriate? */
    /* free in flush_blk_queue */
    bh = (struct buffer_head *) kmalloc(sizeof(struct buffer_head), 
					GFP_KERNEL);
    if (!bh)
    {
      printk(KERN_ALERT "ERROR: bh is null\n");
      BUG();
    }

    /* set just the important bits of the buffer header */
    memset (bh, 0, sizeof (struct buffer_head));

    bh->b_blocknr = blk_ring->tx_ring[index].block_number;   /* block number */
    bh->b_size = blk_ring->tx_ring[index].block_size;          /* block size */
    bh->b_dev = blk_ring->tx_ring[index].device;   /* device (B_FREE = free) */
    bh->b_rsector = blk_ring->tx_ring[index].sector_number; /* sector number */
                                                    
    bh->b_data = phys_to_virt(blk_ring->tx_ring[index].buffer);
                                                          /* ptr to data blk */
    bh->b_count.counter = 1;                       /* users using this block */
    bh->b_xen_request = (void *)blk_request;           /* save block request */
    

    if (blk_ring->tx_ring[index].operation == XEN_BLOCK_WRITE)
    {
      bh->b_state = ((1 << BH_JBD) |                  /* buffer state bitmap */
		     (1 << BH_Mapped) |
		     (1 << BH_Req) |
		     (1 << BH_Dirty) |
		     (1 << BH_Uptodate));
      operation = WRITE;
    }
    else
    {
      bh->b_state = (1 << BH_Mapped);                 /* buffer state bitmap */
      operation = READ;
    }

    /* save meta data about request */
    memcpy(&blk_request->request,                    /* NEED COPY_FROM_USER? */
	   &blk_ring->tx_ring[index], sizeof(blk_ring_entry_t));
    blk_request->bh = bh;
    blk_request->domain = current;                    /* save current domain */

    /* dispatch single block request */
    ll_rw_block(operation, 1, &bh);                        /* linux top half */
    rq = blk_get_queue(bh->b_rdev);                         
    generic_unplug_device(rq);                          /* linux bottom half */

    return 0;
}

/*
 * initialize_block_io
 *
 * initialize everything for block io 
 * called from arch/i386/setup.c::start_of_day
 */

void initialize_block_io ()
{
  int loop;

  INIT_LIST_HEAD(&free_queue);
  INIT_LIST_HEAD(&pending_queue);
  INIT_LIST_HEAD(&io_done_queue);
  
  spin_lock_init(&free_queue_lock);
  spin_lock_init(&pending_queue_lock);
  spin_lock_init(&io_done_queue_lock);

  for (loop = 0; loop < XEN_BLK_REQUEST_LIST_SIZE; loop++)
  {
    list_add_tail(&blk_request_list[loop].queue, &free_queue);
  }

  /*
   * if bit i is true then domain i has work for us to do.
   */
  pending_work = 0;

  return;
}


#ifdef DEBUG

/*
 * debug dump_queue
 * arguments: queue head, name of queue
 */
void dump_queue(struct list_head *queue, char *name)
{
  struct list_head *list;
  int loop = 0;

  printk ("QUEUE %s %lx   n: %lx, p: %lx\n", name,  (unsigned long)queue,
	  (unsigned long) queue->next, (unsigned long) queue->prev);
  list_for_each (list, queue)
  {
    printk ("  %s %d : %lx   n: %lx, p: %lx\n", name, loop++, 
	    (unsigned long)list,
	    (unsigned long)list->next, (unsigned long)list->prev);
  }
}

void dump_queue_head(struct list_head *queue, char *name)
{
  struct list_head *list;
  int loop = 0;

  printk ("QUEUE %s %lx   n: %lx, p: %lx\n", name,  (unsigned long)queue,
	  (unsigned long) queue->next, (unsigned long) queue->prev);
  list_for_each (list, queue)
  {
    printk ("      %d : %lx   n: %lx, p: %lx\n", loop++, 
	    (unsigned long)list,
	    (unsigned long)list->next, (unsigned long)list->prev);
    if (loop >= 5) return;
  }
}

#endif /* DEBUG */


#define debug_block_size 200000
#define debug_output_size 10

static int    countx = 0;
static char * arrayx[debug_block_size];
static int    outputx = 0;

void
printx (char * string)
{
  char * s;

  s = (char *) kmalloc(strlen(string), GFP_KERNEL);
  strcpy (s, string);
  arrayx[countx++] = s;

  if (countx >= debug_block_size)
  {
    countx = 0;
    printk (KERN_ALERT "printx wrap\n");
  }

}

void
dumpx (char *buffer, int count)
{
  int loop;
  int start;

  sprintf (buffer, "debug dump\n");

  /*
  for (loop = outputx;
       loop < outputx + debug_output_size && loop < countx; 
       loop ++)
  {
    sprintf (buffer, "%s%02d:%s\n", buffer, loop, arrayx[loop]);
  }
  outputx = loop;
  */
  
  if (count == 0 || count > countx)
  {
    start = 0;
  }
  else
  {
    start = countx - count;
  }

  printk (KERN_ALERT "DUMPX BUFFER\n");
  for (loop = start; loop < countx; loop++)
  {
    printk (KERN_ALERT "%4d %s\n", loop, arrayx[loop]);
  }
  printk (KERN_ALERT "DUMPX bye bye\n");
}

