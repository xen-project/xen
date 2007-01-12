/*
 * Architecture specific parts of the Floppy driver
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1995
 *
 * Modifications for Xen are Copyright (c) 2004, Keir Fraser.
 */
#ifndef __ASM_XEN_X86_64_FLOPPY_H
#define __ASM_XEN_X86_64_FLOPPY_H

#include <linux/vmalloc.h>

/*
 * The DMA channel used by the floppy controller cannot access data at
 * addresses >= 16MB
 *
 * Went back to the 1MB limit, as some people had problems with the floppy
 * driver otherwise. It doesn't matter much for performance anyway, as most
 * floppy accesses go through the track buffer.
 */
#define _CROSS_64KB(a,s,vdma) \
(!(vdma) && ((unsigned long)(a)/K_64 != ((unsigned long)(a) + (s) - 1) / K_64))

/* XEN: Hit DMA paths on the head. This trick from asm-m68k/floppy.h. */
#include <asm/dma.h>
#undef MAX_DMA_ADDRESS
#define MAX_DMA_ADDRESS 0
#define CROSS_64KB(a,s) (0)

#define fd_inb(port)			inb_p(port)
#define fd_outb(value,port)		outb_p(value,port)

#define fd_request_dma()        (0)
#define fd_free_dma()           ((void)0)
#define fd_enable_irq()         enable_irq(FLOPPY_IRQ)
#define fd_disable_irq()        disable_irq(FLOPPY_IRQ)
#define fd_free_irq()		free_irq(FLOPPY_IRQ, NULL)
#define fd_get_dma_residue()    vdma_get_dma_residue(FLOPPY_DMA)
/*
 * Do not use vmalloc/vfree: floppy_release_irq_and_dma() gets called from
 * softirq context via motor_off_callback. A generic bug we happen to trigger.
 */
#define fd_dma_mem_alloc(size)	__get_free_pages(GFP_KERNEL|__GFP_NORETRY, get_order(size))
#define fd_dma_mem_free(addr, size) free_pages(addr, get_order(size))
#define fd_dma_setup(addr, size, mode, io) vdma_dma_setup(addr, size, mode, io)

static int virtual_dma_count;
static int virtual_dma_residue;
static char *virtual_dma_addr;
static int virtual_dma_mode;
static int doing_pdma;

static irqreturn_t floppy_hardint(int irq, void *dev_id, struct pt_regs * regs)
{
	register unsigned char st;

#undef TRACE_FLPY_INT

#ifdef TRACE_FLPY_INT
	static int calls=0;
	static int bytes=0;
	static int dma_wait=0;
#endif
	if (!doing_pdma)
		return floppy_interrupt(irq, dev_id, regs);

#ifdef TRACE_FLPY_INT
	if(!calls)
		bytes = virtual_dma_count;
#endif

	{
		register int lcount;
		register char *lptr;

		st = 1;
		for(lcount=virtual_dma_count, lptr=virtual_dma_addr; 
		    lcount; lcount--, lptr++) {
			st=inb(virtual_dma_port+4) & 0xa0 ;
			if(st != 0xa0) 
				break;
			if(virtual_dma_mode)
				outb_p(*lptr, virtual_dma_port+5);
			else
				*lptr = inb_p(virtual_dma_port+5);
		}
		virtual_dma_count = lcount;
		virtual_dma_addr = lptr;
		st = inb(virtual_dma_port+4);
	}

#ifdef TRACE_FLPY_INT
	calls++;
#endif
	if(st == 0x20)
		return IRQ_HANDLED;
	if(!(st & 0x20)) {
		virtual_dma_residue += virtual_dma_count;
		virtual_dma_count=0;
#ifdef TRACE_FLPY_INT
		printk("count=%x, residue=%x calls=%d bytes=%d dma_wait=%d\n", 
		       virtual_dma_count, virtual_dma_residue, calls, bytes,
		       dma_wait);
		calls = 0;
		dma_wait=0;
#endif
		doing_pdma = 0;
		floppy_interrupt(irq, dev_id, regs);
		return IRQ_HANDLED;
	}
#ifdef TRACE_FLPY_INT
	if(!virtual_dma_count)
		dma_wait++;
#endif
	return IRQ_HANDLED;
}

static void fd_disable_dma(void)
{
	doing_pdma = 0;
	virtual_dma_residue += virtual_dma_count;
	virtual_dma_count=0;
}

static int vdma_get_dma_residue(unsigned int dummy)
{
	return virtual_dma_count + virtual_dma_residue;
}


static int fd_request_irq(void)
{
	return request_irq(FLOPPY_IRQ, floppy_hardint,SA_INTERRUPT,
					   "floppy", NULL);
}

#if 0
static unsigned long vdma_mem_alloc(unsigned long size)
{
	return (unsigned long) vmalloc(size);

}

static void vdma_mem_free(unsigned long addr, unsigned long size)
{
	vfree((void *)addr);
}
#endif

static int vdma_dma_setup(char *addr, unsigned long size, int mode, int io)
{
	doing_pdma = 1;
	virtual_dma_port = io;
	virtual_dma_mode = (mode  == DMA_MODE_WRITE);
	virtual_dma_addr = addr;
	virtual_dma_count = size;
	virtual_dma_residue = 0;
	return 0;
}

/* XEN: This trick to force 'virtual DMA' is from include/asm-m68k/floppy.h. */
#define FDC1 xen_floppy_init()
static int FDC2 = -1;

static int xen_floppy_init(void)
{
	use_virtual_dma = 1;
	can_use_virtual_dma = 1;
	return 0x3f0;
}

/*
 * Floppy types are stored in the rtc's CMOS RAM and so rtc_lock
 * is needed to prevent corrupted CMOS RAM in case "insmod floppy"
 * coincides with another rtc CMOS user.		Paul G.
 */
#define FLOPPY0_TYPE	({				\
	unsigned long flags;				\
	unsigned char val;				\
	spin_lock_irqsave(&rtc_lock, flags);		\
	val = (CMOS_READ(0x10) >> 4) & 15;		\
	spin_unlock_irqrestore(&rtc_lock, flags);	\
	val;						\
})

#define FLOPPY1_TYPE	({				\
	unsigned long flags;				\
	unsigned char val;				\
	spin_lock_irqsave(&rtc_lock, flags);		\
	val = CMOS_READ(0x10) & 15;			\
	spin_unlock_irqrestore(&rtc_lock, flags);	\
	val;						\
})

#define N_FDC 2
#define N_DRIVE 8

#define FLOPPY_MOTOR_MASK 0xf0

#define EXTRA_FLOPPY_PARAMS

#endif /* __ASM_XEN_X86_64_FLOPPY_H */
