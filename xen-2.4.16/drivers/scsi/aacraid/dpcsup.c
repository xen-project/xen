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
 *  dpcsup.c
 *
 * Abstract: All DPC processing routines for the cyclone board occur here.
 *
 *
 */

#include <xeno/config.h>
/* #include <xeno/kernel.h> */
#include <xeno/init.h>
#include <xeno/types.h>
#include <xeno/sched.h>
#include <xeno/pci.h>
/*  #include <xeno/spinlock.h> */
/*  #include <xeno/slab.h> */
/*  #include <xeno/completion.h> */
#include <xeno/blk.h>
/*  #include <asm/semaphore.h> */
#include "scsi.h"
#include "hosts.h"

#include "aacraid.h"

/**
 *	aac_response_normal	-	Handle command replies
 *	@q: Queue to read from
 *
 *	This DPC routine will be run when the adapter interrupts us to let us
 *	know there is a response on our normal priority queue. We will pull off
 *	all QE there are and wake up all the waiters before exiting. We will
 *	take a spinlock out on the queue before operating on it.
 */

unsigned int aac_response_normal(struct aac_queue * q)
{
	struct aac_dev * dev = q->dev;
	struct aac_entry *entry;
	struct hw_fib * hwfib;
	struct fib * fib;
	int consumed = 0;
	unsigned long flags;

	spin_lock_irqsave(q->lock, flags);	

	/*
	 *	Keep pulling response QEs off the response queue and waking
	 *	up the waiters until there are no more QEs. We then return
	 *	back to the system. If no response was requesed we just
	 *	deallocate the Fib here and continue.
	 */
	while(aac_consumer_get(dev, q, &entry))
	{
		int fast;

		fast = (int) (entry->addr & 0x01);
		hwfib = addr2fib(entry->addr & ~0x01);
		aac_consumer_free(dev, q, HostNormRespQueue);
		fib = &dev->fibs[hwfib->header.SenderData];
		/*
		 *	Remove this fib from the Outstanding I/O queue.
		 *	But only if it has not already been timed out.
		 *
		 *	If the fib has been timed out already, then just 
		 *	continue. The caller has already been notified that
		 *	the fib timed out.
		 */
		if (!(fib->flags & FIB_CONTEXT_FLAG_TIMED_OUT)) {
			list_del(&fib->queue);
			dev->queues->queue[AdapNormCmdQueue].numpending--;
		} else {
			printk(KERN_WARNING "aacraid: FIB timeout (%x).\n", fib->flags);
			continue;
		}
		spin_unlock_irqrestore(q->lock, flags);

		if (fast) {
			/*
			 *	Doctor the fib
			 */
			*(u32 *)hwfib->data = cpu_to_le32(ST_OK);
			hwfib->header.XferState |= cpu_to_le32(AdapterProcessed);
		}

		FIB_COUNTER_INCREMENT(aac_config.FibRecved);

		if (hwfib->header.Command == cpu_to_le16(NuFileSystem))
		{
			u32 *pstatus = (u32 *)hwfib->data;
			if (*pstatus & cpu_to_le32(0xffff0000))
				*pstatus = cpu_to_le32(ST_OK);
		}
		if (hwfib->header.XferState & cpu_to_le32(NoResponseExpected | Async)) 
		{
	        	if (hwfib->header.XferState & cpu_to_le32(NoResponseExpected))
				FIB_COUNTER_INCREMENT(aac_config.NoResponseRecved);
			else 
				FIB_COUNTER_INCREMENT(aac_config.AsyncRecved);
			/*
			 *	NOTE:  we cannot touch the fib after this
			 *	    call, because it may have been deallocated.
			 */
			fib->callback(fib->callback_data, fib);
		} else {
#if 0
			unsigned long flagv;
			spin_lock_irqsave(&fib->event_lock, flagv);
#endif
			fib->done = 1;
#if 0
			up(&fib->event_wait);
			spin_unlock_irqrestore(&fib->event_lock, flagv);
#endif
			FIB_COUNTER_INCREMENT(aac_config.NormalRecved);
		}
		consumed++;
		spin_lock_irqsave(q->lock, flags);
	}

	if (consumed > aac_config.peak_fibs)
		aac_config.peak_fibs = consumed;
	if (consumed == 0) 
		aac_config.zero_fibs++;

	spin_unlock_irqrestore(q->lock, flags);
	return 0;
}


/**
 *	aac_command_normal	-	handle commands
 *	@q: queue to process
 *
 *	This DPC routine will be queued when the adapter interrupts us to 
 *	let us know there is a command on our normal priority queue. We will 
 *	pull off all QE there are and wake up all the waiters before exiting.
 *	We will take a spinlock out on the queue before operating on it.
 */
 
unsigned int aac_command_normal(struct aac_queue *q)
{
	struct aac_dev * dev = q->dev;
	struct aac_entry *entry;
	unsigned long flags;

	spin_lock_irqsave(q->lock, flags);

	/*
	 *	Keep pulling response QEs off the response queue and waking
	 *	up the waiters until there are no more QEs. We then return
	 *	back to the system.
	 */
	while(aac_consumer_get(dev, q, &entry))
	{
		struct hw_fib * fib;
		fib = addr2fib(entry->addr);

		if (dev->aif_thread) {
		        list_add_tail(&fib->header.FibLinks, &q->cmdq);
	 	        aac_consumer_free(dev, q, HostNormCmdQueue);
#if 0
		        wake_up_interruptible(&q->cmdready);
#endif
		} else {
			struct fib fibctx;
	 	        aac_consumer_free(dev, q, HostNormCmdQueue);
			spin_unlock_irqrestore(q->lock, flags);
			memset(&fibctx, 0, sizeof(struct fib));
			fibctx.type = FSAFS_NTC_FIB_CONTEXT;
			fibctx.size = sizeof(struct fib);
			fibctx.fib = fib;
			fibctx.data = fib->data;
			fibctx.dev = dev;
			/*
			 *	Set the status of this FIB
			 */
			*(u32 *)fib->data = cpu_to_le32(ST_OK);
			fib_adapter_complete(&fibctx, sizeof(u32));
			spin_lock_irqsave(q->lock, flags);
		}		
	}
	spin_unlock_irqrestore(q->lock, flags);
	return 0;
}
