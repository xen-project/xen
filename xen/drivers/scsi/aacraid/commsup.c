/*
 *	Adaptec AAC series RAID controller driver
 *	(c) Copyright 2001 Red Hat Inc.	<alan@redhat.com>
 *
 * based on the old aacraid driver that is..

 * Adaptec aacraid device driver for Linux.
 *
 * Copyright (c) 2000 Adaptec, Inc. (aacraid@adaptec.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Module Name:
 *  commsup.c
 *
 * Abstract: Contain all routines that are required for FSA host/adapter
 *    commuication.
 *
 *
 */

#include <xeno/config.h>
/* #include <xeno/kernel.h> */
#include <xeno/init.h>
#include <xeno/types.h>
#include <xeno/sched.h>
#include <xeno/pci.h>
#include <xeno/spinlock.h>

#include <xeno/interrupt.h> /* tasklet stuff */

/*  #include <xeno/slab.h> */
/*  #include <xeno/completion.h> */
/*  #include <asm/semaphore.h> */
#include <xeno/blk.h>
#include <xeno/delay.h>
#include "scsi.h"
#include "hosts.h"

#include "aacraid.h"

/**
 *	fib_map_alloc		-	allocate the fib objects
 *	@dev: Adapter to allocate for
 *
 *	Allocate and map the shared PCI space for the FIB blocks used to
 *	talk to the Adaptec firmware.
 */
 
static int fib_map_alloc(struct aac_dev *dev)
{
    if((dev->hw_fib_va = 
	pci_alloc_consistent(dev->pdev, sizeof(struct hw_fib) * AAC_NUM_FIB, 
			     &dev->hw_fib_pa))==NULL)
	return -ENOMEM;
    return 0;
}

/**
 *	fib_map_free		-	free the fib objects
 *	@dev: Adapter to free
 *
 *	Free the PCI mappings and the memory allocated for FIB blocks
 *	on this adapter.
 */

void fib_map_free(struct aac_dev *dev)
{
    pci_free_consistent(dev->pdev, sizeof(struct hw_fib) * AAC_NUM_FIB, 
			dev->hw_fib_va, dev->hw_fib_pa);
}

/**
 *	fib_setup	-	setup the fibs
 *	@dev: Adapter to set up
 *
 *	Allocate the PCI space for the fibs, map it and then intialise the
 *	fib area, the unmapped fib data and also the free list
 */

int fib_setup(struct aac_dev * dev)
{
    struct fib *fibptr;
    struct hw_fib *fib;
    dma_addr_t fibpa;
    int i;
    
    if(fib_map_alloc(dev)<0)
	return -ENOMEM;
    
    fib = dev->hw_fib_va;
    fibpa = dev->hw_fib_pa;
    memset(fib, 0, sizeof(struct hw_fib) * AAC_NUM_FIB);
    /*
     *	Initialise the fibs
     */
    for (i = 0, fibptr = &dev->fibs[i]; i < AAC_NUM_FIB; i++, fibptr++) 
    {
	fibptr->dev = dev;
	fibptr->fib = fib;
	fibptr->data = (void *) fibptr->fib->data;
	fibptr->next = fibptr+1;	/* Forward chain the fibs */
#if 0
	init_MUTEX_LOCKED(&fibptr->event_wait);
#endif
	spin_lock_init(&fibptr->event_lock);
	fib->header.XferState = cpu_to_le32(0xffffffff);
	fib->header.SenderSize = cpu_to_le16(sizeof(struct hw_fib));
	fibptr->logicaladdr = (unsigned long) fibpa;
	fib = (struct hw_fib *)((unsigned char *)fib + sizeof(struct hw_fib));
	fibpa = fibpa + sizeof(struct hw_fib);
    }
    /*
     *	Add the fib chain to the free list
     */
    dev->fibs[AAC_NUM_FIB-1].next = NULL;
    /*
     *	Enable this to debug out of queue space
     */
    dev->free_fib = &dev->fibs[0];
    return 0;
}

/**
 *	fib_alloc	-	allocate a fib
 *	@dev: Adapter to allocate the fib for
 *
 *	Allocate a fib from the adapter fib pool. If the pool is empty we
 *	wait for fibs to become free.
 */
 
struct fib * fib_alloc(struct aac_dev *dev)
{
    struct fib * fibptr;
    unsigned long flags;
    
    spin_lock_irqsave(&dev->fib_lock, flags);
    fibptr = dev->free_fib;	
    if(!fibptr)
	BUG();
    dev->free_fib = fibptr->next;
    spin_unlock_irqrestore(&dev->fib_lock, flags);
    /*
     *	Set the proper node type code and node byte size
     */
    fibptr->type = FSAFS_NTC_FIB_CONTEXT;
    fibptr->size = sizeof(struct fib);
    /*
     *	Null out fields that depend on being zero at the start of
     *	each I/O
     */
    fibptr->fib->header.XferState = cpu_to_le32(0);
    fibptr->callback = NULL;
    fibptr->callback_data = NULL;
    
    return fibptr;
}

/**
 *	fib_free	-	free a fib
 *	@fibptr: fib to free up
 *
 *	Frees up a fib and places it on the appropriate queue
 *	(either free or timed out)
 */
 
void fib_free(struct fib * fibptr)
{
    unsigned long flags;
    
    spin_lock_irqsave(&fibptr->dev->fib_lock, flags);
    
    if (fibptr->flags & FIB_CONTEXT_FLAG_TIMED_OUT) {
	aac_config.fib_timeouts++;
	fibptr->next = fibptr->dev->timeout_fib;
	fibptr->dev->timeout_fib = fibptr;
    } else {
	if (fibptr->fib->header.XferState != 0) {
	    printk(KERN_WARNING "fib_free, XferState != 0, "
		   "fibptr = 0x%p, XferState = 0x%x\n", 
		   (void *)fibptr, fibptr->fib->header.XferState);
	}
	fibptr->next = fibptr->dev->free_fib;
	fibptr->dev->free_fib = fibptr;
    }	
    spin_unlock_irqrestore(&fibptr->dev->fib_lock, flags);
}

/**
 *	fib_init	-	initialise a fib
 *	@fibptr: The fib to initialize
 *	
 *	Set up the generic fib fields ready for use
 */
 
void fib_init(struct fib *fibptr)
{
    struct hw_fib *fib = fibptr->fib;
    
    fib->header.StructType = FIB_MAGIC;
    fib->header.Size = cpu_to_le16(sizeof(struct hw_fib));
    fib->header.XferState = cpu_to_le32(HostOwned | FibInitialized | 
					FibEmpty | FastResponseCapable);
    fib->header.SenderFibAddress = cpu_to_le32(0);
    fib->header.ReceiverFibAddress = cpu_to_le32(0);
    fib->header.SenderSize = cpu_to_le16(sizeof(struct hw_fib));
}

/**
 *	fib_deallocate		-	deallocate a fib
 *	@fibptr: fib to deallocate
 *
 *	Will deallocate and return to the free pool the FIB pointed to by the
 *	caller.
 */
 
void fib_dealloc(struct fib * fibptr)
{
    struct hw_fib *fib = fibptr->fib;
    if(fib->header.StructType != FIB_MAGIC) 
	BUG();
    fib->header.XferState = cpu_to_le32(0);        
}

/*
 *	Commuication primitives define and support the queuing method we use to
 *	support host to adapter commuication. All queue accesses happen through
 *	these routines and are the only routines which have a knowledge of the
 *	 how these queues are implemented.
 */
 
/**
 *	aac_get_entry		-	get a queue entry
 *	@dev: Adapter
 *	@qid: Queue Number
 *	@entry: Entry return
 *	@index: Index return
 *	@nonotify: notification control
 *
 *	With a priority the routine returns a queue entry if the queue has free entries. If the queue
 *	is full(no free entries) than no entry is returned and the function returns 0 otherwise 1 is
 *	returned.
 */
 
static int aac_get_entry (struct aac_dev * dev, u32 qid, struct aac_entry **entry, u32 * index, unsigned long *nonotify)
{
    struct aac_queue * q;

    /*
     *	All of the queues wrap when they reach the end, so we check
     *	to see if they have reached the end and if they have we just
     *	set the index back to zero. This is a wrap. You could or off
     *	the high bits in all updates but this is a bit faster I think.
     */

    q = &dev->queues->queue[qid];
	
    *index = le32_to_cpu(*(q->headers.producer));
    if (*index - 2 == le32_to_cpu(*(q->headers.consumer)))
	*nonotify = 1; 

    if (qid == AdapHighCmdQueue) {
	if (*index >= ADAP_HIGH_CMD_ENTRIES)
	    *index = 0;
    } else if (qid == AdapNormCmdQueue) {
	if (*index >= ADAP_NORM_CMD_ENTRIES) 
	    *index = 0; /* Wrap to front of the Producer Queue. */
    }
    else if (qid == AdapHighRespQueue) 
    {
	if (*index >= ADAP_HIGH_RESP_ENTRIES)
	    *index = 0;
    }
    else if (qid == AdapNormRespQueue) 
    {
	if (*index >= ADAP_NORM_RESP_ENTRIES) 
	    *index = 0; /* Wrap to front of the Producer Queue. */
    }
    else BUG();

    if (*index + 1 == le32_to_cpu(*(q->headers.consumer))) { /* Queue full */
	printk(KERN_WARNING "Queue %d full, %ld outstanding.\n", 
	       qid, q->numpending);
	return 0;
    } else {
	*entry = q->base + *index;
	return 1;
    }
}   

/**
 *	aac_queue_get		-	get the next free QE
 *	@dev: Adapter
 *	@index: Returned index
 *	@priority: Priority of fib
 *	@fib: Fib to associate with the queue entry
 *	@wait: Wait if queue full
 *	@fibptr: Driver fib object to go with fib
 *	@nonotify: Don't notify the adapter
 *
 *	Gets the next free QE off the requested priorty adapter command
 *	queue and associates the Fib with the QE. The QE represented by
 *	index is ready to insert on the queue when this routine returns
 *	success.
 */

static int aac_queue_get(struct aac_dev * dev, u32 * index, u32 qid, struct hw_fib * fib, int wait, struct fib * fibptr, unsigned long *nonotify)
{
    struct aac_entry * entry = NULL;
    int map = 0;
    struct aac_queue * q = &dev->queues->queue[qid];
		
    spin_lock_irqsave(q->lock, q->SavedIrql);
	    
    if (qid == AdapHighCmdQueue || qid == AdapNormCmdQueue) 
    {
	/*  if no entries wait for some if caller wants to */
	while (!aac_get_entry(dev, qid, &entry, index, nonotify)) 
	{
	    printk(KERN_ERR "GetEntries failed\n");
	}
	/*
	 *	Setup queue entry with a command, status and fib mapped
	 */
	entry->size = cpu_to_le32(le16_to_cpu(fib->header.Size));
	map = 1;
    }
    else if (qid == AdapHighRespQueue || qid == AdapNormRespQueue)
    {
	while(!aac_get_entry(dev, qid, &entry, index, nonotify)) 
	{
	    /* if no entries wait for some if caller wants to */
	}
	/*
	 *	Setup queue entry with command, status and fib mapped
	 */
	entry->size = cpu_to_le32(le16_to_cpu(fib->header.Size));
	entry->addr = cpu_to_le32(fib->header.SenderFibAddress);     		/* Restore adapters pointer to the FIB */
	fib->header.ReceiverFibAddress = fib->header.SenderFibAddress;		/* Let the adapter now where to find its data */
	map = 0;
    } 
    /*
     *	If MapFib is true than we need to map the Fib and put pointers
     *	in the queue entry.
     */
    if (map)
	entry->addr = cpu_to_le32((unsigned long)(fibptr->logicaladdr));
    return 0;
}


/**
 *	aac_insert_entry	-	insert a queue entry
 *	@dev: Adapter
 *	@index: Index of entry to insert
 *	@qid: Queue number
 *	@nonotify: Suppress adapter notification
 *
 *	Gets the next free QE off the requested priorty adapter command
 *	queue and associates the Fib with the QE. The QE represented by
 *	index is ready to insert on the queue when this routine returns
 *	success.
 */
 
static int aac_insert_entry(struct aac_dev * dev, u32 index, u32 qid, unsigned long nonotify) 
{
    struct aac_queue * q = &dev->queues->queue[qid];

    if(q == NULL)
	BUG();
    *(q->headers.producer) = cpu_to_le32(index + 1);
    spin_unlock_irqrestore(q->lock, q->SavedIrql);

    if (qid == AdapHighCmdQueue ||
	qid == AdapNormCmdQueue ||
	qid == AdapHighRespQueue ||
	qid == AdapNormRespQueue)
    {
	if (!nonotify)
	    aac_adapter_notify(dev, qid);
    }
    else
	printk("Suprise insert!\n");
    return 0;
}

/*
 *	Define the highest level of host to adapter communication routines. 
 *	These routines will support host to adapter FS commuication. These 
 *	routines have no knowledge of the commuication method used. This level
 *	sends and receives FIBs. This level has no knowledge of how these FIBs
 *	get passed back and forth.
 */

/**
 *	fib_send	-	send a fib to the adapter
 *	@command: Command to send
 *	@fibptr: The fib
 *	@size: Size of fib data area
 *	@priority: Priority of Fib
 *	@wait: Async/sync select
 *	@reply: True if a reply is wanted
 *	@callback: Called with reply
 *	@callback_data: Passed to callback
 *
 *	Sends the requested FIB to the adapter and optionally will wait for a
 *	response FIB. If the caller does not wish to wait for a response than
 *	an event to wait on must be supplied. This event will be set when a
 *	response FIB is received from the adapter.
 */
 
int fib_send(u16 command, struct fib * fibptr, unsigned long size,  int priority, int wait, int reply, fib_callback callback, void * callback_data)
{
    u32 index;
    u32 qid;
    struct aac_dev * dev = fibptr->dev;
    unsigned long nointr = 0;
    struct hw_fib * fib = fibptr->fib;
    struct aac_queue * q;
    unsigned long flags = 0;

    if (!(le32_to_cpu(fib->header.XferState) & HostOwned))
	return -EBUSY;
    /*
     *	There are 5 cases with the wait and reponse requested flags. 
     *	The only invalid cases are if the caller requests to wait and
     *	does not request a response and if the caller does not want a
     *	response and the Fibis not allocated from pool. If a response
     *	is not requesed the Fib will just be deallocaed by the DPC
     *	routine when the response comes back from the adapter. No
     *	further processing will be done besides deleting the Fib. We 
     *	will have a debug mode where the adapter can notify the host
     *	it had a problem and the host can log that fact.
     */
    if (wait && !reply) {
	return -EINVAL;
    } else if (!wait && reply) {
	fib->header.XferState |= cpu_to_le32(Async | ResponseExpected);
	FIB_COUNTER_INCREMENT(aac_config.AsyncSent);
    } else if (!wait && !reply) {
	fib->header.XferState |= cpu_to_le32(NoResponseExpected);
	FIB_COUNTER_INCREMENT(aac_config.NoResponseSent);
    } else if (wait && reply) {
	fib->header.XferState |= cpu_to_le32(ResponseExpected);
	FIB_COUNTER_INCREMENT(aac_config.NormalSent);
    } 
    /*
     *	Map the fib into 32bits by using the fib number
     */
    fib->header.SenderData = fibptr-&dev->fibs[0];	/* for callback */
    /*
     *	Set FIB state to indicate where it came from and if we want a
     *	response from the adapter. Also load the command from the
     *	caller.
     *
     *	Map the hw fib pointer as a 32bit value
     */
    fib->header.SenderFibAddress = fib2addr(fib);
    fib->header.Command = cpu_to_le16(command);
    fib->header.XferState |= cpu_to_le32(SentFromHost);
    fibptr->fib->header.Flags = 0; /* Zero flags field - its internal only */
    /*
     *	Set the size of the Fib we want to send to the adapter
     */
    fib->header.Size = cpu_to_le16(sizeof(struct aac_fibhdr) + size);
    if (le16_to_cpu(fib->header.Size) > le16_to_cpu(fib->header.SenderSize)) {
	return -EMSGSIZE;
    }                
    /*
     *	Get a queue entry connect the FIB to it and send an notify
     *	the adapter a command is ready.
     */
    if (priority == FsaHigh) {
	fib->header.XferState |= cpu_to_le32(HighPriority);
	qid = AdapHighCmdQueue;
    } else {
	fib->header.XferState |= cpu_to_le32(NormalPriority);
	qid = AdapNormCmdQueue;
    }
    q = &dev->queues->queue[qid];

    if(wait)
	spin_lock_irqsave(&fibptr->event_lock, flags);

    if(aac_queue_get( dev, &index, qid, fib, 1, fibptr, &nointr)<0)
	return -EWOULDBLOCK;
    dprintk((KERN_DEBUG "fib_send: inserting a queue entry at index %d.\n",
	     index));
    dprintk((KERN_DEBUG "Fib contents:.\n"));
    dprintk((KERN_DEBUG "  Command =               %d.\n", 
	     fib->header.Command));
    dprintk((KERN_DEBUG "  XferState  =            %x.\n", 
	     fib->header.XferState));
    /*
     *	Fill in the Callback and CallbackContext if we are not
     *	going to wait.
     */
    if (!wait) {
	fibptr->callback = callback;
	fibptr->callback_data = callback_data;
    }
    FIB_COUNTER_INCREMENT(aac_config.FibsSent);
    list_add_tail(&fibptr->queue, &q->pendingq);
    q->numpending++;

    fibptr->done = 0;

    if(aac_insert_entry(dev, index, qid, 
			(nointr & aac_config.irq_mod)) < 0)
	return -EWOULDBLOCK;
    /*
     *	If the caller wanted us to wait for response wait now. 
     */
    
    if (wait) {
	spin_unlock_irqrestore(&fibptr->event_lock, flags);
#if 0
	down(&fibptr->event_wait);
#endif
#ifdef TRY_TASKLET
        /*
         * XXX KAF: Well, this is pretty gross. We should probably
         * do_softirq() after scheduling the tasklet, as long as we
         * are _sure_ we hold no locks here...
         */
	printk("about to softirq aac_command_thread...\n"); 
	while (!fibptr->done) { 
            tasklet_schedule(&aac_command_tasklet);
	    mdelay(100); 
	}
	printk("back from softirq cmd thread and fibptr->done!\n"); 
#else 
	printk("about to bail at aac_command_thread...\n"); 
	while (!fibptr->done) { 
	    mdelay(100); 
	    aac_command_thread(dev); 
	}
	printk("back from command thread and fibptr->done!\n"); 
#endif
/*  if(fibptr->done == 0) */
/*  			BUG(); */
			
	if((fibptr->flags & FIB_CONTEXT_FLAG_TIMED_OUT))
	    return -ETIMEDOUT;
	else
	    return 0;
    }
    /*
     *	If the user does not want a response than return success otherwise
     *	return pending
     */
    if (reply)
	return -EINPROGRESS;
    else
	return 0;
}

/** 
 *	aac_consumer_get	-	get the top of the queue
 *	@dev: Adapter
 *	@q: Queue
 *	@entry: Return entry
 *
 *      Will return a pointer to the entry on the top of the queue
 * 	requested that we are a consumer of, and return the address of
 * 	the queue entry. It does * not change the state of the queue.
 */

int aac_consumer_get(struct aac_dev * dev, struct aac_queue * q, struct aac_entry **entry)
{
    u32 index;
    int status;

    if (*q->headers.producer == *q->headers.consumer) {
	status = 0;
    } else {
	/*
	 *	The consumer index must be wrapped if we have reached
	 *	the end of the queue, else we just use the entry
	 *	pointed to by the header index
	 */
	if (le32_to_cpu(*q->headers.consumer) >= q->entries) 
	    index = 0;		
	else
	    index = le32_to_cpu(*q->headers.consumer);
	*entry = q->base + index;
	status = 1;
    }
    return(status);
}

int aac_consumer_avail(struct aac_dev *dev, struct aac_queue * q)
{
    return (*q->headers.producer != *q->headers.consumer);
}


/**
 *	aac_consumer_free	-	free consumer entry
 *	@dev: Adapter
 *	@q: Queue
 *	@qid: Queue ident
 *
 *	Frees up the current top of the queue we are a consumer of. If the
 *	queue was full notify the producer that the queue is no longer full.
 */

void aac_consumer_free(struct aac_dev * dev, struct aac_queue *q, u32 qid)
{
    int wasfull = 0;
    u32 notify;

    if (*q->headers.producer+1 == *q->headers.consumer)
	wasfull = 1;
        
    if (le32_to_cpu(*q->headers.consumer) >= q->entries)
	*q->headers.consumer = cpu_to_le32(1);
    else
	*q->headers.consumer = 
	    cpu_to_le32(le32_to_cpu(*q->headers.consumer)+1);
        
    if (wasfull) {
	switch (qid) {

	case HostNormCmdQueue:
	    notify = HostNormCmdNotFull;
	    break;
	case HostHighCmdQueue:
	    notify = HostHighCmdNotFull;
	    break;
	case HostNormRespQueue:
	    notify = HostNormRespNotFull;
	    break;
	case HostHighRespQueue:
	    notify = HostHighRespNotFull;
	    break;
	default:
	    BUG();
	    return;
	}
	aac_adapter_notify(dev, notify);
    }
}        

/**
 *	fib_adapter_complete	-	complete adapter issued fib
 *	@fibptr: fib to complete
 *	@size: size of fib
 *
 *	Will do all necessary work to complete a FIB that was sent from
 *	the adapter.
 */

int fib_adapter_complete(struct fib * fibptr, unsigned short size)
{
    struct hw_fib * fib = fibptr->fib;
    struct aac_dev * dev = fibptr->dev;
    unsigned long nointr = 0;

    if (le32_to_cpu(fib->header.XferState) == 0)
	return 0;
    /*
     *	If we plan to do anything check the structure type first.
     */ 
    if ( fib->header.StructType != FIB_MAGIC ) {
	return -EINVAL;
    }
    /*
     *	This block handles the case where the adapter had sent us a
     *	command and we have finished processing the command. We
     *	call completeFib when we are done processing the command 
     *	and want to send a response back to the adapter. This will 
     *	send the completed cdb to the adapter.
     */
    if (fib->header.XferState & cpu_to_le32(SentFromAdapter)) {
	fib->header.XferState |= cpu_to_le32(HostProcessed);
	if (fib->header.XferState & cpu_to_le32(HighPriority)) {
	    u32 index;
	    if (size) 
	    {
		size += sizeof(struct aac_fibhdr);
		if (size > le16_to_cpu(fib->header.SenderSize))
		    return -EMSGSIZE;
		fib->header.Size = cpu_to_le16(size);
	    }
	    if(aac_queue_get(dev, &index, AdapHighRespQueue, 
			     fib, 1, NULL, &nointr) < 0) {
		return -EWOULDBLOCK;
	    }
	    if (aac_insert_entry(dev, index, AdapHighRespQueue,  
				 (nointr & (int)aac_config.irq_mod)) != 0) {
	    }
	}
	else if (fib->header.XferState & NormalPriority) 
	{
	    u32 index;

	    if (size) {
		size += sizeof(struct aac_fibhdr);
		if (size > le16_to_cpu(fib->header.SenderSize)) 
		    return -EMSGSIZE;
		fib->header.Size = cpu_to_le16(size);
	    }
	    if (aac_queue_get(dev, &index, AdapNormRespQueue, 
			      fib, 1, NULL, &nointr) < 0) 
		return -EWOULDBLOCK;
	    if (aac_insert_entry(dev, index, AdapNormRespQueue, 
				 (nointr & (int)aac_config.irq_mod)) != 0) 
	    {
	    }
	}
    }
    else 
    {
	printk(KERN_WARNING 
	       "fib_adapter_complete: Unknown xferstate detected.\n");
	BUG();
    }   
    return 0;
}

/**
 *	fib_complete	-	fib completion handler
 *	@fib: FIB to complete
 *
 *	Will do all necessary work to complete a FIB.
 */
 
int fib_complete(struct fib * fibptr)
{
    struct hw_fib * fib = fibptr->fib;

    /*
     *	Check for a fib which has already been completed
     */

    if (fib->header.XferState == cpu_to_le32(0))
	return 0;
    /*
     *	If we plan to do anything check the structure type first.
     */ 

    if (fib->header.StructType != FIB_MAGIC)
	return -EINVAL;
    /*
     *	This block completes a cdb which orginated on the host and we 
     *	just need to deallocate the cdb or reinit it. At this point the
     *	command is complete that we had sent to the adapter and this
     *	cdb could be reused.
     */
    if((fib->header.XferState & cpu_to_le32(SentFromHost)) &&
       (fib->header.XferState & cpu_to_le32(AdapterProcessed)))
    {
	fib_dealloc(fibptr);
    }
    else if(fib->header.XferState & cpu_to_le32(SentFromHost))
    {
	/*
	 *	This handles the case when the host has aborted the I/O
	 *	to the adapter because the adapter is not responding
	 */
	fib_dealloc(fibptr);
    } else if(fib->header.XferState & cpu_to_le32(HostOwned)) {
	fib_dealloc(fibptr);
    } else {
	BUG();
    }   
    return 0;
}

/**
 *	aac_printf	-	handle printf from firmware
 *	@dev: Adapter
 *	@val: Message info
 *
 *	Print a message passed to us by the controller firmware on the
 *	Adaptec board
 */

void aac_printf(struct aac_dev *dev, u32 val)
{
    int length = val & 0xffff;
    int level = (val >> 16) & 0xffff;
    char *cp = dev->printfbuf;
	
    /*
     *	The size of the printfbuf is set in port.c
     *	There is no variable or define for it
     */
    if (length > 255)
	length = 255;
    if (cp[length] != 0)
	cp[length] = 0;
    if (level == LOG_HIGH_ERROR)
	printk(KERN_WARNING "aacraid:%s", cp);
    else
	printk(KERN_INFO "aacraid:%s", cp);
    memset(cp, 0,  256);
}


/**
 *	aac_handle_aif		-	Handle a message from the firmware
 *	@dev: Which adapter this fib is from
 *	@fibptr: Pointer to fibptr from adapter
 *
 *	This routine handles a driver notify fib from the adapter and
 *	dispatches it to the appropriate routine for handling.
 */

static void aac_handle_aif(struct aac_dev * dev, struct fib * fibptr)
{
    struct hw_fib * fib = fibptr->fib;
    /*
     * Set the status of this FIB to be Invalid parameter.
     *
     *	*(u32 *)fib->data = ST_INVAL;
     */
    *(u32 *)fib->data = cpu_to_le32(ST_OK);
    fib_adapter_complete(fibptr, sizeof(u32));
}

/**
 *	aac_command_thread	-	command processing thread
 *	@dev: Adapter to monitor
 *
 *	Waits on the commandready event in it's queue. When the event gets set
 *	it will pull FIBs off it's queue. It will continue to pull FIBs off
 *	until the queue is empty. When the queue is empty it will wait for
 *	more FIBs.
 */
 
#ifndef TRY_TASKLET
DECLARE_TASKLET_DISABLED(aac_command_tasklet, aac_command_thread, 0);
int aac_command_thread(struct aac_dev * dev)
{
#else
int aac_command_thread(unsigned long data)
{   
    struct aac_dev *dev = (struct aac_dev *)data; 
#endif
    struct hw_fib *fib, *newfib;
    struct fib fibptr; /* for error logging */
    struct aac_queue_block *queues = dev->queues;
    struct aac_fib_context *fibctx;
    unsigned long flags;
#if 0
    DECLARE_WAITQUEUE(wait, current);
#endif

    /*
     *	We can only have one thread per adapter for AIF's.
     */
    printk("aac_command_'thread': entered.\n"); 
    if (dev->aif_thread)
	return -EINVAL;

#if 0
    /*
     *	Set up the name that will appear in 'ps'
     *	stored in  task_struct.comm[16].
     */
    sprintf(current->comm, "aacraid");
    daemonize();
#endif

    /*
     *	Let the DPC know it has a place to send the AIF's to.
     */
    dev->aif_thread = 1;
    memset(&fibptr, 0, sizeof(struct fib));
#if 0
    add_wait_queue(&queues->queue[HostNormCmdQueue].cmdready, &wait);
    set_current_state(TASK_INTERRUPTIBLE);
#endif
//    while(1) 
    {

	printk("aac_command_thread: in 'loop'\n"); 
	spin_lock_irqsave(queues->queue[HostNormCmdQueue].lock, flags);
	printk("flags = %x\n", flags); 
	while(!list_empty(&(queues->queue[HostNormCmdQueue].cmdq))) {
	    struct list_head *entry;
	    struct aac_aifcmd * aifcmd;

#if 0
	    set_current_state(TASK_RUNNING);
#endif

		
	    entry = queues->queue[HostNormCmdQueue].cmdq.next;
	    list_del(entry);
			
	    spin_unlock_irqrestore(queues->queue[HostNormCmdQueue].lock,flags);
	    fib = list_entry(entry, struct hw_fib, header.FibLinks);
	    printk("aac_command_thread: got fib \n"); 
	    /*
	     *	We will process the FIB here or pass it to a 
	     *	worker thread that is TBD. We Really can't 
	     *	do anything at this point since we don't have
	     *	anything defined for this thread to do.
	     */
	    memset(&fibptr, 0, sizeof(struct fib));
	    fibptr.type = FSAFS_NTC_FIB_CONTEXT;
	    fibptr.size = sizeof( struct fib );
	    fibptr.fib = fib;
	    fibptr.data = fib->data;
	    fibptr.dev = dev;
	    /*
	     *	We only handle AifRequest fibs from the adapter.
	     */
	    aifcmd = (struct aac_aifcmd *) fib->data;
	    if (aifcmd->command == le16_to_cpu(AifCmdDriverNotify)) {
		printk("aac_command_thread: handling aif... :-( \n"); 
		aac_handle_aif(dev, &fibptr);
	    } else {
		/* The u32 here is important and intended. We are using
		   32bit wrapping time to fit the adapter field */
		u32 time_now, time_last;
		unsigned long flagv;
		
		time_now = jiffies/HZ;

		spin_lock_irqsave(&dev->fib_lock, flagv);
		entry = dev->fib_list.next;
				/*
				 * For each Context that is on the 
				 * fibctxList, make a copy of the
				 * fib, and then set the event to wake up the
				 * thread that is waiting for it.
				 */
		while (entry != &dev->fib_list) {
		    /*
		     * Extract the fibctx
		     */
		    fibctx = list_entry(entry, struct aac_fib_context, next);
		    /*
		     * Check if the queue is getting
		     * backlogged
		     */
		    if (fibctx->count > 20)
		    {
			time_last = fibctx->jiffies;
			/*
			 * Has it been > 2 minutes 
			 * since the last read off
			 * the queue?
			 */
			if ((time_now - time_last) > 120) {
			    entry = entry->next;
			    aac_close_fib_context(dev, fibctx);
			    continue;
			}
		    }
		    /*
		     * Warning: no sleep allowed while
		     * holding spinlock
		     */
		    newfib = kmalloc(sizeof(struct hw_fib), GFP_ATOMIC);
		    if (newfib) {
			/*
			 * Make the copy of the FIB
			 */
			memcpy(newfib, fib, sizeof(struct hw_fib));
			/*
			 * Put the FIB onto the
			 * fibctx's fibs
			 */
			list_add_tail(&newfib->header.FibLinks, &fibctx->fibs);
			fibctx->count++;
#if 0
			/* 
			 * Set the event to wake up the
			 * thread that will waiting.
			 */
			up(&fibctx->wait_sem);
#endif
		    } else {
			printk(KERN_WARNING "aifd: didn't allocate NewFib.\n");
		    }
		    entry = entry->next;
		}
				/*
				 *	Set the status of this FIB
				 */
		*(u32 *)fib->data = cpu_to_le32(ST_OK);
		fib_adapter_complete(&fibptr, sizeof(u32));
		spin_unlock_irqrestore(&dev->fib_lock, flagv);
	    }
	    spin_lock_irqsave(queues->queue[HostNormCmdQueue].lock, flags);
	}
	/*
	 *	There are no more AIF's
	 */
	spin_unlock_irqrestore(queues->queue[HostNormCmdQueue].lock, flags);
#if 0
	schedule();

	if(signal_pending(current))
	    break;
	set_current_state(TASK_INTERRUPTIBLE);
#endif

    }
    
#if 0
    remove_wait_queue(&queues->queue[HostNormCmdQueue].cmdready, &wait);
    dev->aif_thread = 0;
    complete_and_exit(&dev->aif_completion, 0);
#else
    mdelay(50); 
    dev->aif_thread = 0;

#endif
    return 0;
}
