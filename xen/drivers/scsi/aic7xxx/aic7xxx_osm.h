/*
 * Adaptec AIC7xxx device driver for Linux.
 *
 * Copyright (c) 1994 John Aycock
 *   The University of Calgary Department of Computer Science.
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
 * $Id: //depot/aic7xxx/linux/drivers/scsi/aic7xxx/aic7xxx_osm.h#82 $
 *
 * Copyright (c) 2000-2001 Adaptec Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 * $Id: //depot/aic7xxx/linux/drivers/scsi/aic7xxx/aic7xxx_osm.h#82 $
 *
 */

#ifndef _AIC7XXX_LINUX_H_
#define _AIC7XXX_LINUX_H_
#include <xeno/lib.h>
#include <xeno/string.h>
#include <xeno/types.h>
#include <xeno/blk.h>
#include <xeno/blkdev.h>
#include <xeno/delay.h>
#include <xeno/ioport.h>
#include <xeno/pci.h>
//#include <xeno/version.h>
#ifndef AHC_MODVERSION_FILE
#define __NO_VERSION__
#endif
#include <xeno/module.h>
#include <asm/byteorder.h>
#include <xeno/notifier.h>

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(x,y,z) (((x)<<16)+((y)<<8)+(z))
#endif

#define LINUX_VERSION_CODE KERNEL_VERSION(2,4,20)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
#include <xeno/interrupt.h> /* For tasklet support. */
#include <xeno/config.h>
#include <xeno/slab.h>
#else
#include <xeno/malloc.h>
#endif

/* Core SCSI definitions */
#include "../scsi.h"
#include "../hosts.h"

/* Name space conflict with BSD queue macros */
#ifdef LIST_HEAD
#undef LIST_HEAD
#endif

#include "cam.h"
#include "queue.h"
#include "scsi_message.h"

/************************* Forward Declarations *******************************/
struct ahc_softc;
typedef struct pci_dev *ahc_dev_softc_t;
typedef Scsi_Cmnd      *ahc_io_ctx_t;

/******************************* Byte Order ***********************************/
#define ahc_htobe16(x)	cpu_to_be16(x)
#define ahc_htobe32(x)	cpu_to_be32(x)
#define ahc_htobe64(x)	cpu_to_be64(x)
#define ahc_htole16(x)	cpu_to_le16(x)
#define ahc_htole32(x)	cpu_to_le32(x)
#define ahc_htole64(x)	cpu_to_le64(x)

#define ahc_be16toh(x)	be16_to_cpu(x)
#define ahc_be32toh(x)	be32_to_cpu(x)
#define ahc_be64toh(x)	be64_to_cpu(x)
#define ahc_le16toh(x)	le16_to_cpu(x)
#define ahc_le32toh(x)	le32_to_cpu(x)
#define ahc_le64toh(x)	le64_to_cpu(x)

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif

#ifndef BYTE_ORDER
#if defined(__BIG_ENDIAN)
#define BYTE_ORDER BIG_ENDIAN
#endif
#if defined(__LITTLE_ENDIAN)
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#endif /* BYTE_ORDER */

/************************* Configuration Data *********************************/
extern int aic7xxx_no_probe;
extern int aic7xxx_detect_complete;
extern Scsi_Host_Template* aic7xxx_driver_template;

/***************************** Bus Space/DMA **********************************/

//#if LINUX_VERSION_CODE > KERNEL_VERSION(2,2,17)
typedef dma_addr_t bus_addr_t;
//#else
//typedef uint32_t bus_addr_t;
//#endif
typedef uint32_t bus_size_t;

typedef enum {
	BUS_SPACE_MEMIO,
	BUS_SPACE_PIO
} bus_space_tag_t;

typedef union {
	u_long		  ioport;
	volatile uint8_t *maddr;
} bus_space_handle_t;

typedef struct bus_dma_segment
{
	bus_addr_t	ds_addr;
	bus_size_t	ds_len;
} bus_dma_segment_t;

struct ahc_linux_dma_tag
{
	bus_size_t	alignment;
	bus_size_t	boundary;
	bus_size_t	maxsize;
};
typedef struct ahc_linux_dma_tag* bus_dma_tag_t;

struct ahc_linux_dmamap
{
	bus_addr_t	bus_addr;
};
typedef struct ahc_linux_dmamap* bus_dmamap_t;

typedef int bus_dma_filter_t(void*, bus_addr_t);
typedef void bus_dmamap_callback_t(void *, bus_dma_segment_t *, int, int);

#define BUS_DMA_WAITOK		0x0
#define BUS_DMA_NOWAIT		0x1
#define BUS_DMA_ALLOCNOW	0x2
#define BUS_DMA_LOAD_SEGS	0x4	/*
					 * Argument is an S/G list not
					 * a single buffer.
					 */

#define BUS_SPACE_MAXADDR	0xFFFFFFFF
#define BUS_SPACE_MAXADDR_32BIT	0xFFFFFFFF
#define BUS_SPACE_MAXSIZE_32BIT	0xFFFFFFFF

int	ahc_dma_tag_create(struct ahc_softc *, bus_dma_tag_t /*parent*/,
			   bus_size_t /*alignment*/, bus_size_t /*boundary*/,
			   bus_addr_t /*lowaddr*/, bus_addr_t /*highaddr*/,
			   bus_dma_filter_t*/*filter*/, void */*filterarg*/,
			   bus_size_t /*maxsize*/, int /*nsegments*/,
			   bus_size_t /*maxsegsz*/, int /*flags*/,
			   bus_dma_tag_t */*dma_tagp*/);

void	ahc_dma_tag_destroy(struct ahc_softc *, bus_dma_tag_t /*tag*/);

int	ahc_dmamem_alloc(struct ahc_softc *, bus_dma_tag_t /*dmat*/,
			 void** /*vaddr*/, int /*flags*/,
			 bus_dmamap_t* /*mapp*/);

void	ahc_dmamem_free(struct ahc_softc *, bus_dma_tag_t /*dmat*/,
			void* /*vaddr*/, bus_dmamap_t /*map*/);

void	ahc_dmamap_destroy(struct ahc_softc *, bus_dma_tag_t /*tag*/,
			   bus_dmamap_t /*map*/);

int	ahc_dmamap_load(struct ahc_softc *ahc, bus_dma_tag_t /*dmat*/,
			bus_dmamap_t /*map*/, void * /*buf*/,
			bus_size_t /*buflen*/, bus_dmamap_callback_t *,
			void */*callback_arg*/, int /*flags*/);

int	ahc_dmamap_unload(struct ahc_softc *, bus_dma_tag_t, bus_dmamap_t);

/*
 * Operations performed by ahc_dmamap_sync().
 */
#define BUS_DMASYNC_PREREAD	0x01	/* pre-read synchronization */
#define BUS_DMASYNC_POSTREAD	0x02	/* post-read synchronization */
#define BUS_DMASYNC_PREWRITE	0x04	/* pre-write synchronization */
#define BUS_DMASYNC_POSTWRITE	0x08	/* post-write synchronization */

/*
 * XXX
 * ahc_dmamap_sync is only used on buffers allocated with
 * the pci_alloc_consistent() API.  Although I'm not sure how
 * this works on architectures with a write buffer, Linux does
 * not have an API to sync "coherent" memory.  Perhaps we need
 * to do an mb()?
 */
#define ahc_dmamap_sync(ahc, dma_tag, dmamap, offset, len, op)

/************************** SCSI Constants/Structures *************************/
#define SCSI_REV_2 2
#define	SCSI_STATUS_OK			0x00
#define	SCSI_STATUS_CHECK_COND		0x02
#define	SCSI_STATUS_COND_MET		0x04
#define	SCSI_STATUS_BUSY		0x08
#define SCSI_STATUS_INTERMED		0x10
#define SCSI_STATUS_INTERMED_COND_MET	0x14
#define SCSI_STATUS_RESERV_CONFLICT	0x18
#define SCSI_STATUS_CMD_TERMINATED	0x22
#define SCSI_STATUS_QUEUE_FULL		0x28

/*
 * 6 byte request sense CDB format.
 */
struct scsi_sense
{
	uint8_t opcode;
	uint8_t byte2;
	uint8_t unused[2];
	uint8_t length;
	uint8_t control;
};

struct scsi_sense_data
{
	uint8_t	error_code;
	uint8_t	segment;
	uint8_t	flags;
	uint8_t	info[4];
	uint8_t	extra_len;
	uint8_t	cmd_spec_info[4];
	uint8_t add_sense_code;
	uint8_t add_sense_code_qual;
	uint8_t	fru;
	uint8_t	sense_key_spec[3];
	uint8_t	extra_bytes[14];
};

struct scsi_inquiry
{ 
	u_int8_t opcode;
	u_int8_t byte2;
#define	SI_EVPD 0x01
	u_int8_t page_code;
	u_int8_t reserved;
	u_int8_t length;
	u_int8_t control;
};

struct scsi_inquiry_data
{
	uint8_t device;
#define	SID_TYPE(inq_data) ((inq_data)->device & 0x1f)
#define	SID_QUAL(inq_data) (((inq_data)->device & 0xE0) >> 5)
#define	SID_QUAL_LU_CONNECTED	0x00	/*
					 * The specified peripheral device
					 * type is currently connected to
					 * logical unit.  If the target cannot
					 * determine whether or not a physical
					 * device is currently connected, it
					 * shall also use this peripheral
					 * qualifier when returning the INQUIRY
					 * data.  This peripheral qualifier
					 * does not mean that the device is
					 * ready for access by the initiator.
					 */
#define	SID_QUAL_LU_OFFLINE	0x01	/*
					 * The target is capable of supporting
					 * the specified peripheral device type
					 * on this logical unit; however, the
					 * physical device is not currently
					 * connected to this logical unit.
					 */
#define SID_QUAL_RSVD		0x02
#define	SID_QUAL_BAD_LU		0x03	/*
					 * The target is not capable of
					 * supporting a physical device on
					 * this logical unit. For this
					 * peripheral qualifier the peripheral
					 * device type shall be set to 1Fh to
					 * provide compatibility with previous
					 * versions of SCSI. All other
					 * peripheral device type values are
					 * reserved for this peripheral
					 * qualifier.
					 */
#define	SID_QUAL_IS_VENDOR_UNIQUE(inq_data) ((SID_QUAL(inq_data) & 0x08) != 0)
	uint8_t dev_qual2;
#define	SID_QUAL2	0x7F
#define	SID_IS_REMOVABLE(inq_data) (((inq_data)->dev_qual2 & 0x80) != 0)
	uint8_t version;
#define SID_ANSI_REV(inq_data) ((inq_data)->version & 0x07)
#define		SCSI_REV_0		0
#define		SCSI_REV_CCS		1
#define		SCSI_REV_2		2
#define		SCSI_REV_SPC		3
#define		SCSI_REV_SPC2		4

#define SID_ECMA	0x38
#define SID_ISO		0xC0
	uint8_t response_format;
#define SID_AENC	0x80
#define SID_TrmIOP	0x40
	uint8_t additional_length;
	uint8_t reserved[2];
	uint8_t flags;
#define	SID_SftRe	0x01
#define	SID_CmdQue	0x02
#define	SID_Linked	0x08
#define	SID_Sync	0x10
#define	SID_WBus16	0x20
#define	SID_WBus32	0x40
#define	SID_RelAdr	0x80
#define SID_VENDOR_SIZE   8
	char	 vendor[SID_VENDOR_SIZE];
#define SID_PRODUCT_SIZE  16
	char	 product[SID_PRODUCT_SIZE];
#define SID_REVISION_SIZE 4
	char	 revision[SID_REVISION_SIZE];
	/*
	 * The following fields were taken from SCSI Primary Commands - 2
	 * (SPC-2) Revision 14, Dated 11 November 1999
	 */
#define	SID_VENDOR_SPECIFIC_0_SIZE	20
	u_int8_t vendor_specific0[SID_VENDOR_SPECIFIC_0_SIZE];
	/*
	 * An extension of SCSI Parallel Specific Values
	 */
#define	SID_SPI_IUS		0x01
#define	SID_SPI_QAS		0x02
#define	SID_SPI_CLOCK_ST	0x00
#define	SID_SPI_CLOCK_DT	0x04
#define	SID_SPI_CLOCK_DT_ST	0x0C
#define	SID_SPI_MASK		0x0F
	uint8_t spi3data;
	uint8_t reserved2;
	/*
	 * Version Descriptors, stored 2 byte values.
	 */
	uint8_t version1[2];
	uint8_t version2[2];
	uint8_t version3[2];
	uint8_t version4[2];
	uint8_t version5[2];
	uint8_t version6[2];
	uint8_t version7[2];
	uint8_t version8[2];

	uint8_t reserved3[22];

#define	SID_VENDOR_SPECIFIC_1_SIZE	160
	uint8_t vendor_specific1[SID_VENDOR_SPECIFIC_1_SIZE];
};

/********************************** Includes **********************************/
/* Host template and function declarations referenced by the template. */
#include "aic7xxx_host.h"

/* Core driver definitions */
#include "aic7xxx.h"

/* SMP support */
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,17)
#include <xeno/spinlock.h>
//#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,93)
//#include <xeno/smp.h>
//#endif

#define AIC7XXX_DRIVER_VERSION  "6.2.8"

/**************************** Front End Queues ********************************/
/*
 * Data structure used to cast the Linux struct scsi_cmnd to something
 * that allows us to use the queue macros.  The linux structure has
 * plenty of space to hold the links fields as required by the queue
 * macros, but the queue macors require them to have the correct type.
 */
struct ahc_cmd_internal {
	/* Area owned by the Linux scsi layer. */
	uint8_t	private[offsetof(struct scsi_cmnd, SCp.Status)];
	union {
		STAILQ_ENTRY(ahc_cmd)	ste;
		LIST_ENTRY(ahc_cmd)	le;
		TAILQ_ENTRY(ahc_cmd)	tqe;
	} links;
	uint32_t			end;
};

struct ahc_cmd {
	union {
		struct ahc_cmd_internal	icmd;
		struct scsi_cmnd	scsi_cmd;
	} un;
};

#define acmd_icmd(cmd) ((cmd)->un.icmd)
#define acmd_scsi_cmd(cmd) ((cmd)->un.scsi_cmd)
#define acmd_links un.icmd.links

/*************************** Device Data Structures ***************************/
/*
 * A per probed device structure used to deal with some error recovery
 * scenarios that the Linux mid-layer code just doesn't know how to
 * handle.  The structure allocated for a device only becomes persistant
 * after a successfully completed inquiry command to the target when
 * that inquiry data indicates a lun is present.
 */
TAILQ_HEAD(ahc_busyq, ahc_cmd);
typedef enum {
	AHC_DEV_UNCONFIGURED	 = 0x01,
	AHC_DEV_FREEZE_TIL_EMPTY = 0x02, /* Freeze queue until active == 0 */
	AHC_DEV_TIMER_ACTIVE	 = 0x04, /* Our timer is active */
	AHC_DEV_ON_RUN_LIST	 = 0x08, /* Queued to be run later */
	AHC_DEV_Q_BASIC		 = 0x10, /* Allow basic device queuing */
	AHC_DEV_Q_TAGGED	 = 0x20, /* Allow full SCSI2 command queueing */
	AHC_DEV_PERIODIC_OTAG	 = 0x40	 /* Send OTAG to prevent starvation */
} ahc_dev_flags;

struct ahc_linux_target;
struct ahc_linux_device {
	TAILQ_ENTRY(ahc_linux_device) links;
	struct		ahc_busyq busyq;

	/*
	 * The number of transactions currently
	 * queued to the device.
	 */
	int			active;

	/*
	 * The currently allowed number of 
	 * transactions that can be queued to
	 * the device.  Must be signed for
	 * conversion from tagged to untagged
	 * mode where the device may have more
	 * than one outstanding active transaction.
	 */
	int			openings;

	/*
	 * A positive count indicates that this
	 * device's queue is halted.
	 */
	u_int			qfrozen;
	
	/*
	 * Cumulative command counter.
	 */
	u_long			commands_issued;

	/*
	 * The number of tagged transactions when
	 * running at our current opening level
	 * that have been successfully received by
	 * this device since the last QUEUE FULL.
	 */
	u_int			tag_success_count;
#define AHC_TAG_SUCCESS_INTERVAL 50

	ahc_dev_flags		flags;

	/*
	 * Per device timer.
	 */
	struct timer_list	timer;

	/*
	 * The high limit for the tags variable.
	 */
	u_int			maxtags;

	/*
	 * The computed number of tags outstanding
	 * at the time of the last QUEUE FULL event.
	 */
	u_int			tags_on_last_queuefull;

	/*
	 * How many times we have seen a queue full
	 * with the same number of tags.  This is used
	 * to stop our adaptive queue depth algorithm
	 * on devices with a fixed number of tags.
	 */
	u_int			last_queuefull_same_count;
#define AHC_LOCK_TAGS_COUNT 50

	/*
	 * How many transactions have been queued
	 * without the device going idle.  We use
	 * this statistic to determine when to issue
	 * an ordered tag to prevent transaction
	 * starvation.  This statistic is only updated
	 * if the AHC_DEV_PERIODIC_OTAG flag is set
	 * on this device.
	 */
	u_int			commands_since_idle_or_otag;
#define AHC_OTAG_THRESH	500

	int			lun;
	struct			ahc_linux_target *target;
};

struct ahc_linux_target {
	struct	ahc_linux_device *devices[AHC_NUM_LUNS];
	int	channel;
	int	target;
	int	refcount;
	struct	ahc_transinfo last_tinfo;
	struct	ahc_softc *ahc;
};

/********************* Definitions Required by the Core ***********************/
/*
 * Number of SG segments we require.  So long as the S/G segments for
 * a particular transaction are allocated in a physically contiguous
 * manner and are allocated below 4GB, the number of S/G segments is
 * unrestricted.
 */
#define        AHC_NSEG 128

/*
 * Per-SCB OSM storage.
 */
struct scb_platform_data {
	struct ahc_linux_device	*dev;
	bus_addr_t		 buf_busaddr;
	uint32_t		 xfer_len;
  //#if LINUX_VERSION_CODE < KERNEL_VERSION(2,3,0)
	uint32_t		 resid;		/* Transfer residual */
  //#endif
};

/*
 * Define a structure used for each host adapter.  All members are
 * aligned on a boundary >= the size of the member to honor the
 * alignment restrictions of the various platforms supported by
 * this driver.
 */
TAILQ_HEAD(ahc_completeq, ahc_cmd);
struct ahc_platform_data {
	/*
	 * Fields accessed from interrupt context.
	 */
	struct ahc_linux_target *targets[AHC_NUM_TARGETS]; 
	TAILQ_HEAD(, ahc_linux_device) device_runq;
	struct ahc_completeq	 completeq;

  //#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,0)
	spinlock_t		 spin_lock;
  //#endif
  //#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	struct tasklet_struct	 runq_tasklet;
  //#endif
	u_int			 qfrozen;
	struct timer_list	 reset_timer;
  //	struct semaphore	 eh_sem;
	struct Scsi_Host        *host;		/* pointer to scsi host */
#define AHC_LINUX_NOIRQ	((uint32_t)~0)
	uint32_t		 irq;		/* IRQ for this adapter */
	uint32_t		 bios_address;
	uint32_t		 mem_busaddr;	/* Mem Base Addr */
	bus_addr_t		 hw_dma_mask;
};

/************************** OS Utility Wrappers *******************************/
#define printf printk
#define M_NOWAIT GFP_ATOMIC
#define M_WAITOK 0
#define malloc(size, type, flags) kmalloc(size, flags)
#define free(ptr, type) kfree(ptr)

static __inline void ahc_delay(long);
static __inline void
ahc_delay(long usec)
{
	/*
	 * udelay on Linux can have problems for
	 * multi-millisecond waits.  Wait at most
	 * 1024us per call.
	 */
	while (usec > 0) {
		udelay(usec % 1024);
		usec -= 1024;
	}
}


/***************************** Low Level I/O **********************************/
#if defined(__powerpc__) || defined(__i386__) || defined(__ia64__)
#define MMAPIO
#endif

static __inline uint8_t ahc_inb(struct ahc_softc * ahc, long port);
static __inline void ahc_outb(struct ahc_softc * ahc, long port, uint8_t val);
static __inline void ahc_outsb(struct ahc_softc * ahc, long port,
			       uint8_t *, int count);
static __inline void ahc_insb(struct ahc_softc * ahc, long port,
			       uint8_t *, int count);

static __inline uint8_t
ahc_inb(struct ahc_softc * ahc, long port)
{
	uint8_t x;
#ifdef MMAPIO

	if (ahc->tag == BUS_SPACE_MEMIO) {
		x = readb(ahc->bsh.maddr + port);
	} else {
		x = inb(ahc->bsh.ioport + port);
	}
#else
	x = inb(ahc->bsh.ioport + port);
#endif
	mb();
	return (x);
}

static __inline void
ahc_outb(struct ahc_softc * ahc, long port, uint8_t val)
{
#ifdef MMAPIO
	if (ahc->tag == BUS_SPACE_MEMIO) {
		writeb(val, ahc->bsh.maddr + port);
	} else {
		outb(val, ahc->bsh.ioport + port);
	}
#else
	outb(val, ahc->bsh.ioport + port);
#endif
	mb();
}

static __inline void
ahc_outsb(struct ahc_softc * ahc, long port, uint8_t *array, int count)
{
	int i;

	/*
	 * There is probably a more efficient way to do this on Linux
	 * but we don't use this for anything speed critical and this
	 * should work.
	 */
	for (i = 0; i < count; i++)
		ahc_outb(ahc, port, *array++);
}

static __inline void
ahc_insb(struct ahc_softc * ahc, long port, uint8_t *array, int count)
{
	int i;

	/*
	 * There is probably a more efficient way to do this on Linux
	 * but we don't use this for anything speed critical and this
	 * should work.
	 */
	for (i = 0; i < count; i++)
		*array++ = ahc_inb(ahc, port);
}

/**************************** Initialization **********************************/
int		ahc_linux_register_host(struct ahc_softc *,
					Scsi_Host_Template *);

uint64_t	ahc_linux_get_memsize(void);

/*************************** Pretty Printing **********************************/

#define off_t unsigned long

struct info_str {
	char *buffer;
	int length;
	off_t offset;
	int pos;
};

void	ahc_format_transinfo(struct info_str *info,
			     struct ahc_transinfo *tinfo);


/******************************** Locking *************************************/
/* Lock protecting internal data structures */
static __inline void ahc_lockinit(struct ahc_softc *);
static __inline void ahc_lock(struct ahc_softc *, unsigned long *flags);
static __inline void ahc_unlock(struct ahc_softc *, unsigned long *flags);

/* Lock held during command compeletion to the upper layer */
static __inline void ahc_done_lockinit(struct ahc_softc *);
static __inline void ahc_done_lock(struct ahc_softc *, unsigned long *flags);
static __inline void ahc_done_unlock(struct ahc_softc *, unsigned long *flags);

/* Lock held during ahc_list manipulation and ahc softc frees */
extern spinlock_t ahc_list_spinlock;
static __inline void ahc_list_lockinit(void);
static __inline void ahc_list_lock(unsigned long *flags);
static __inline void ahc_list_unlock(unsigned long *flags);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,93)
static __inline void
ahc_lockinit(struct ahc_softc *ahc)
{
	spin_lock_init(&ahc->platform_data->spin_lock);
}

static __inline void
ahc_lock(struct ahc_softc *ahc, unsigned long *flags)
{
	*flags = 0;
	spin_lock_irqsave(&ahc->platform_data->spin_lock, *flags);
}

static __inline void
ahc_unlock(struct ahc_softc *ahc, unsigned long *flags)
{
	spin_unlock_irqrestore(&ahc->platform_data->spin_lock, *flags);
}

static __inline void
ahc_done_lockinit(struct ahc_softc *ahc)
{
	/* We don't own the iorequest lock, so we don't initialize it. */
}

static __inline void
ahc_done_lock(struct ahc_softc *ahc, unsigned long *flags)
{
	*flags = 0;
	spin_lock_irqsave(&io_request_lock, *flags);
}

static __inline void
ahc_done_unlock(struct ahc_softc *ahc, unsigned long *flags)
{
	spin_unlock_irqrestore(&io_request_lock, *flags);
}

static __inline void
ahc_list_lockinit()
{
	spin_lock_init(&ahc_list_spinlock);
}

static __inline void
ahc_list_lock(unsigned long *flags)
{
	*flags = 0;
	spin_lock_irqsave(&ahc_list_spinlock, *flags);
}

static __inline void
ahc_list_unlock(unsigned long *flags)
{
	spin_unlock_irqrestore(&ahc_list_spinlock, *flags);
}

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,1,0) */

ahc_lockinit(struct ahc_softc *ahc)
{
}

static __inline void
ahc_lock(struct ahc_softc *ahc, unsigned long *flags)
{
	*flags = 0;
	save_flags(*flags);
	cli();
}

static __inline void
ahc_unlock(struct ahc_softc *ahc, unsigned long *flags)
{
	restore_flags(*flags);
}

static __inline void
ahc_done_lockinit(struct ahc_softc *ahc)
{
}

static __inline void
ahc_done_lock(struct ahc_softc *ahc, unsigned long *flags)
{
	/*
	 * The done lock is always held while
	 * the ahc lock is held so blocking
	 * interrupts again would have no effect.
	 */
}

static __inline void
ahc_done_unlock(struct ahc_softc *ahc, unsigned long *flags)
{
}

static __inline void
ahc_list_lockinit()
{
}

static __inline void
ahc_list_lock(unsigned long *flags)
{
	*flags = 0;
	save_flags(*flags);
	cli();
}

static __inline void
ahc_list_unlock(unsigned long *flags)
{
	restore_flags(*flags);
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,1,0) */

/******************************* PCI Definitions ******************************/
/*
 * PCIM_xxx: mask to locate subfield in register
 * PCIR_xxx: config register offset
 * PCIC_xxx: device class
 * PCIS_xxx: device subclass
 * PCIP_xxx: device programming interface
 * PCIV_xxx: PCI vendor ID (only required to fixup ancient devices)
 * PCID_xxx: device ID
 */
#define PCIR_DEVVENDOR		0x00
#define PCIR_VENDOR		0x00
#define PCIR_DEVICE		0x02
#define PCIR_COMMAND		0x04
#define PCIM_CMD_PORTEN		0x0001
#define PCIM_CMD_MEMEN		0x0002
#define PCIM_CMD_BUSMASTEREN	0x0004
#define PCIM_CMD_MWRICEN	0x0010
#define PCIM_CMD_PERRESPEN	0x0040
#define PCIR_STATUS		0x06
#define PCIR_REVID		0x08
#define PCIR_PROGIF		0x09
#define PCIR_SUBCLASS		0x0a
#define PCIR_CLASS		0x0b
#define PCIR_CACHELNSZ		0x0c
#define PCIR_LATTIMER		0x0d
#define PCIR_HEADERTYPE		0x0e
#define PCIM_MFDEV		0x80
#define PCIR_BIST		0x0f
#define PCIR_CAP_PTR		0x34

/* config registers for header type 0 devices */
#define PCIR_MAPS	0x10
#define PCIR_SUBVEND_0	0x2c
#define PCIR_SUBDEV_0	0x2e

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
extern struct pci_driver aic7xxx_pci_driver;
#endif

typedef enum
{
	AHC_POWER_STATE_D0,
	AHC_POWER_STATE_D1,
	AHC_POWER_STATE_D2,
	AHC_POWER_STATE_D3
} ahc_power_state;

void ahc_power_state_change(struct ahc_softc *ahc,
			    ahc_power_state new_state);
/**************************** VL/EISA Routines ********************************/
int			 aic7770_linux_probe(Scsi_Host_Template *);
int			 aic7770_map_registers(struct ahc_softc *ahc,
					       u_int port);
int			 aic7770_map_int(struct ahc_softc *ahc, u_int irq);

/******************************* PCI Routines *********************************/
/*
 * We need to use the bios32.h routines if we are kernel version 2.1.92 or less.
 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,1,92)
#if defined(__sparc_v9__) || defined(__powerpc__)
#error "PPC and Sparc platforms are only support under 2.1.92 and above"
#endif
#include <xeno/bios32.h>
#endif

int			 ahc_linux_pci_probe(Scsi_Host_Template *);
int			 ahc_pci_map_registers(struct ahc_softc *ahc);
int			 ahc_pci_map_int(struct ahc_softc *ahc);

static __inline uint32_t ahc_pci_read_config(ahc_dev_softc_t pci,
					     int reg, int width);

static __inline uint32_t
ahc_pci_read_config(ahc_dev_softc_t pci, int reg, int width)
{
	switch (width) {
	case 1:
	{
		uint8_t retval;

		pci_read_config_byte(pci, reg, &retval);
		return (retval);
	}
	case 2:
	{
		uint16_t retval;
		pci_read_config_word(pci, reg, &retval);
		return (retval);
	}
	case 4:
	{
		uint32_t retval;
		pci_read_config_dword(pci, reg, &retval);
		return (retval);
	}
	default:
		panic("ahc_pci_read_config: Read size too big");
		/* NOTREACHED */
		return (0);
	}
}

static __inline void ahc_pci_write_config(ahc_dev_softc_t pci,
					  int reg, uint32_t value,
					  int width);

static __inline void
ahc_pci_write_config(ahc_dev_softc_t pci, int reg, uint32_t value, int width)
{
	switch (width) {
	case 1:
		pci_write_config_byte(pci, reg, value);
		break;
	case 2:
		pci_write_config_word(pci, reg, value);
		break;
	case 4:
		pci_write_config_dword(pci, reg, value);
		break;
	default:
		panic("ahc_pci_write_config: Write size too big");
		/* NOTREACHED */
	}
}

static __inline int ahc_get_pci_function(ahc_dev_softc_t);
static __inline int
ahc_get_pci_function(ahc_dev_softc_t pci)
{
	return (PCI_FUNC(pci->devfn));
}

static __inline int ahc_get_pci_slot(ahc_dev_softc_t);
static __inline int
ahc_get_pci_slot(ahc_dev_softc_t pci)
{
	return (PCI_SLOT(pci->devfn));
}

static __inline int ahc_get_pci_bus(ahc_dev_softc_t);
static __inline int
ahc_get_pci_bus(ahc_dev_softc_t pci)
{
	return (pci->bus->number);
}

static __inline void ahc_flush_device_writes(struct ahc_softc *);
static __inline void
ahc_flush_device_writes(struct ahc_softc *ahc)
{
	/* XXX Is this sufficient for all architectures??? */
	ahc_inb(ahc, INTSTAT);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,3,0)
#define pci_map_sg(pdev, sg_list, nseg, direction) (nseg)
#define pci_unmap_sg(pdev, sg_list, nseg, direction)
#define sg_dma_address(sg) (VIRT_TO_BUS((sg)->address))
#define sg_dma_len(sg) ((sg)->length)
#define pci_map_single(pdev, buffer, bufflen, direction) \
	(VIRT_TO_BUS(buffer))
#define pci_unmap_single(pdev, buffer, buflen, direction)
#endif

/*********************** Transaction Access Wrappers **************************/
static __inline void ahc_set_transaction_status(struct scb *, uint32_t);
static __inline
void ahc_set_transaction_status(struct scb *scb, uint32_t status)
{
	scb->io_ctx->result &= ~(CAM_STATUS_MASK << 16);
	scb->io_ctx->result |= status << 16;
}

static __inline void ahc_set_scsi_status(struct scb *, uint32_t);
static __inline
void ahc_set_scsi_status(struct scb *scb, uint32_t status)
{
	scb->io_ctx->result &= ~0xFFFF;
	scb->io_ctx->result |= status;
}

static __inline uint32_t ahc_get_transaction_status(struct scb *);
static __inline
uint32_t ahc_get_transaction_status(struct scb *scb)
{
	return ((scb->io_ctx->result >> 16) & CAM_STATUS_MASK);
}

static __inline uint32_t ahc_get_scsi_status(struct scb *);
static __inline
uint32_t ahc_get_scsi_status(struct scb *scb)
{
	return (scb->io_ctx->result & 0xFFFF);
}

static __inline void ahc_set_transaction_tag(struct scb *, int, u_int);
static __inline
void ahc_set_transaction_tag(struct scb *scb, int enabled, u_int type)
{
	/*
	 * Nothing to do for linux as the incoming transaction
	 * has no concept of tag/non tagged, etc.
	 */
}

static __inline u_long ahc_get_transfer_length(struct scb *);
static __inline
u_long ahc_get_transfer_length(struct scb *scb)
{
	return (scb->platform_data->xfer_len);
}

static __inline int ahc_get_transfer_dir(struct scb *);
static __inline
int ahc_get_transfer_dir(struct scb *scb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,40)
	return (scb->io_ctx->sc_data_direction);
#else
	if (scb->io_ctx->bufflen == 0)
		return (CAM_DIR_NONE);

	switch(scb->io_ctx->cmnd[0]) {
	case 0x08:  /* READ(6)  */
	case 0x28:  /* READ(10) */
	case 0xA8:  /* READ(12) */
		return (CAM_DIR_IN);
        case 0x0A:  /* WRITE(6)  */
        case 0x2A:  /* WRITE(10) */
        case 0xAA:  /* WRITE(12) */
		return (CAM_DIR_OUT);
        default:
		return (CAM_DIR_NONE);
        }
#endif
}

static __inline void ahc_set_residual(struct scb *, u_long);
static __inline
void ahc_set_residual(struct scb *scb, u_long resid)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	scb->io_ctx->resid = resid;
#else
	scb->platform_data->resid = resid;
#endif
}

static __inline void ahc_set_sense_residual(struct scb *, u_long);
static __inline
void ahc_set_sense_residual(struct scb *scb, u_long resid)
{
	/* This can't be reported in Linux */
}

static __inline u_long ahc_get_residual(struct scb *);
static __inline
u_long ahc_get_residual(struct scb *scb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	return (scb->io_ctx->resid);
#else
	return (scb->platform_data->resid);
#endif
}

static __inline int ahc_perform_autosense(struct scb *);
static __inline
int ahc_perform_autosense(struct scb *scb)
{
	/*
	 * We always perform autosense in Linux.
	 * On other platforms this is set on a
	 * per-transaction basis.
	 */
	return (1);
}

static __inline uint32_t
ahc_get_sense_bufsize(struct ahc_softc *ahc, struct scb *scb)
{
	return (sizeof(struct scsi_sense_data));
}

static __inline void ahc_notify_xfer_settings_change(struct ahc_softc *,
						     struct ahc_devinfo *);
static __inline void
ahc_notify_xfer_settings_change(struct ahc_softc *ahc,
				struct ahc_devinfo *devinfo)
{
	/* Nothing to do here for linux */
}

static __inline void ahc_platform_scb_free(struct ahc_softc *ahc,
					   struct scb *scb);
static __inline void
ahc_platform_scb_free(struct ahc_softc *ahc, struct scb *scb)
{
	ahc->flags &= ~AHC_RESOURCE_SHORTAGE;
}

int	ahc_platform_alloc(struct ahc_softc *ahc, void *platform_arg);
void	ahc_platform_free(struct ahc_softc *ahc);
void	ahc_platform_freeze_devq(struct ahc_softc *ahc, struct scb *scb);
static __inline void	ahc_freeze_scb(struct scb *scb);
static __inline void
ahc_freeze_scb(struct scb *scb)
{
	/* Noting to do here for linux */
}

void	ahc_platform_set_tags(struct ahc_softc *ahc,
			      struct ahc_devinfo *devinfo, ahc_queue_alg);
int	ahc_platform_abort_scbs(struct ahc_softc *ahc, int target,
				char channel, int lun, u_int tag,
				role_t role, uint32_t status);
void	ahc_linux_isr(int irq, void *dev_id, struct pt_regs * regs);
void	ahc_platform_flushwork(struct ahc_softc *ahc);
int	ahc_softc_comp(struct ahc_softc *, struct ahc_softc *);
void	ahc_done(struct ahc_softc*, struct scb*);
void	ahc_send_async(struct ahc_softc *, char channel,
		       u_int target, u_int lun, ac_code, void *);
void	ahc_print_path(struct ahc_softc *, struct scb *);
void	ahc_platform_dump_card_state(struct ahc_softc *ahc);

#ifdef CONFIG_PCI
#define AHC_PCI_CONFIG 1
#else
#define AHC_PCI_CONFIG 0
#endif
#define bootverbose aic7xxx_verbose
extern int aic7xxx_verbose;
#endif /* _AIC7XXX_LINUX_H_ */
