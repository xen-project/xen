/*
 * Adaptec AIC79xx device driver for Linux.
 *
 * $Id: //depot/aic7xxx/linux/drivers/scsi/aic7xxx/aic79xx_osm.c#36 $
 *
 * --------------------------------------------------------------------------
 * Copyright (c) 1994-2000 Justin T. Gibbs.
 * Copyright (c) 1997-1999 Doug Ledford
 * Copyright (c) 2000-2002 Adaptec Inc.
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
 */

/*
 * This is the only file where module.h should
 * embed module global version info.
 */
#define AHD_MODVERSION_FILE

#include "aic79xx_osm.h"
#include "aic79xx_inline.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
#include <linux/init.h>		/* __setup */
#endif

#include "../sd.h"		/* For geometry detection */

#include <linux/mm.h>		/* For fetching system memory size */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,0)
/*
 * Lock protecting manipulation of the ahd softc list.
 */
spinlock_t ahd_list_spinlock;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,3,0)
struct proc_dir_entry proc_scsi_aic79xx = {
	PROC_SCSI_AIC79XX, 7, "aic79xx",
	S_IFDIR | S_IRUGO | S_IXUGO, 2,
	0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};
#endif

/*
 * Set this to the delay in seconds after SCSI bus reset.
 * Note, we honor this only for the initial bus reset.
 * The scsi error recovery code performs its own bus settle
 * delay handling for error recovery actions.
 */
#ifdef CONFIG_AIC79XX_RESET_DELAY_MS
#define AIC79XX_RESET_DELAY CONFIG_AIC79XX_RESET_DELAY_MS
#else
#define AIC79XX_RESET_DELAY 5000
#endif

/*
 * To change the default number of tagged transactions allowed per-device,
 * add a line to the lilo.conf file like:
 * append="aic79xx=verbose,tag_info:{{32,32,32,32},{32,32,32,32}}"
 * which will result in the first four devices on the first two
 * controllers being set to a tagged queue depth of 32.
 *
 * The tag_commands is an array of 16 to allow for wide and twin adapters.
 * Twin adapters will use indexes 0-7 for channel 0, and indexes 8-15
 * for channel 1.
 */
typedef struct {
	uint16_t tag_commands[16];	/* Allow for wide/twin adapters. */
} adapter_tag_info_t;

/*
 * Modify this as you see fit for your system.
 *
 * 0			tagged queuing disabled
 * 1 <= n <= 253	n == max tags ever dispatched.
 *
 * The driver will throttle the number of commands dispatched to a
 * device if it returns queue full.  For devices with a fixed maximum
 * queue depth, the driver will eventually determine this depth and
 * lock it in (a console message is printed to indicate that a lock
 * has occurred).  On some devices, queue full is returned for a temporary
 * resource shortage.  These devices will return queue full at varying
 * depths.  The driver will throttle back when the queue fulls occur and
 * attempt to slowly increase the depth over time as the device recovers
 * from the resource shortage.
 *
 * In this example, the first line will disable tagged queueing for all
 * the devices on the first probed aic79xx adapter.
 *
 * The second line enables tagged queueing with 4 commands/LUN for IDs
 * (0, 2-11, 13-15), disables tagged queueing for ID 12, and tells the
 * driver to attempt to use up to 64 tags for ID 1.
 *
 * The third line is the same as the first line.
 *
 * The fourth line disables tagged queueing for devices 0 and 3.  It
 * enables tagged queueing for the other IDs, with 16 commands/LUN
 * for IDs 1 and 4, 127 commands/LUN for ID 8, and 4 commands/LUN for
 * IDs 2, 5-7, and 9-15.
 */

/*
 * NOTE: The below structure is for reference only, the actual structure
 *       to modify in order to change things is just below this comment block.
adapter_tag_info_t aic79xx_tag_info[] =
{
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	{{4, 64, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 0, 4, 4, 4}},
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	{{0, 16, 4, 0, 16, 4, 4, 4, 127, 4, 4, 4, 4, 4, 4, 4}}
};
*/

#ifdef CONFIG_AIC79XX_CMDS_PER_DEVICE
#define AIC79XX_CMDS_PER_DEVICE CONFIG_AIC79XX_CMDS_PER_DEVICE
#else
#define AIC79XX_CMDS_PER_DEVICE AHD_MAX_QUEUE
#endif

#define AIC79XX_CONFIGED_TAG_COMMANDS {					\
	AIC79XX_CMDS_PER_DEVICE, AIC79XX_CMDS_PER_DEVICE,		\
	AIC79XX_CMDS_PER_DEVICE, AIC79XX_CMDS_PER_DEVICE,		\
	AIC79XX_CMDS_PER_DEVICE, AIC79XX_CMDS_PER_DEVICE,		\
	AIC79XX_CMDS_PER_DEVICE, AIC79XX_CMDS_PER_DEVICE,		\
	AIC79XX_CMDS_PER_DEVICE, AIC79XX_CMDS_PER_DEVICE,		\
	AIC79XX_CMDS_PER_DEVICE, AIC79XX_CMDS_PER_DEVICE,		\
	AIC79XX_CMDS_PER_DEVICE, AIC79XX_CMDS_PER_DEVICE,		\
	AIC79XX_CMDS_PER_DEVICE, AIC79XX_CMDS_PER_DEVICE		\
}

/*
 * By default, use the number of commands specified by
 * the users kernel configuration.
 */
static adapter_tag_info_t aic79xx_tag_info[] =
{
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS},
	{AIC79XX_CONFIGED_TAG_COMMANDS}
};

/*
 * By default, read streaming is disabled.  In theory,
 * read streaming should enhance performance, but early
 * U320 drive firmware actually performs slower with
 * read streaming enabled.
 */
#ifdef CONFIG_AIC79XX_ENABLE_RD_STRM
#define AIC79XX_CONFIGED_RD_STRM 0xFFFF
#else
#define AIC79XX_CONFIGED_RD_STRM 0
#endif

static uint16_t aic79xx_rd_strm_info[] =
{
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM,
	AIC79XX_CONFIGED_RD_STRM
};

/*
 * There should be a specific return value for this in scsi.h, but
 * it seems that most drivers ignore it.
 */
#define DID_UNDERFLOW   DID_ERROR

void
ahd_print_path(struct ahd_softc *ahd, struct scb *scb)
{
	printk("(scsi%d:%c:%d:%d): ",
	       ahd->platform_data->host->host_no,
	       scb != NULL ? SCB_GET_CHANNEL(ahd, scb) : 'X',
	       scb != NULL ? SCB_GET_TARGET(ahd, scb) : -1,
	       scb != NULL ? SCB_GET_LUN(scb) : -1);
}

/*
 * XXX - these options apply unilaterally to _all_ adapters
 *       cards in the system.  This should be fixed.  Exceptions to this
 *       rule are noted in the comments.
 */

/*
 * Skip the scsi bus reset.  Non 0 make us skip the reset at startup.  This
 * has no effect on any later resets that might occur due to things like
 * SCSI bus timeouts.
 */
static uint32_t aic79xx_no_reset;

/*
 * Certain PCI motherboards will scan PCI devices from highest to lowest,
 * others scan from lowest to highest, and they tend to do all kinds of
 * strange things when they come into contact with PCI bridge chips.  The
 * net result of all this is that the PCI card that is actually used to boot
 * the machine is very hard to detect.  Most motherboards go from lowest
 * PCI slot number to highest, and the first SCSI controller found is the
 * one you boot from.  The only exceptions to this are when a controller
 * has its BIOS disabled.  So, we by default sort all of our SCSI controllers
 * from lowest PCI slot number to highest PCI slot number.  We also force
 * all controllers with their BIOS disabled to the end of the list.  This
 * works on *almost* all computers.  Where it doesn't work, we have this
 * option.  Setting this option to non-0 will reverse the order of the sort
 * to highest first, then lowest, but will still leave cards with their BIOS
 * disabled at the very end.  That should fix everyone up unless there are
 * really strange cirumstances.
 */
static int aic79xx_reverse_scan = 0;

/*
 * Should we force EXTENDED translation on a controller.
 *     0 == Use whatever is in the SEEPROM or default to off
 *     1 == Use whatever is in the SEEPROM or default to on
 */
static uint32_t aic79xx_extended = 0;

/*
 * PCI bus parity checking of the Adaptec controllers.  This is somewhat
 * dubious at best.  To my knowledge, this option has never actually
 * solved a PCI parity problem, but on certain machines with broken PCI
 * chipset configurations, it can generate tons of false error messages.
 * It's included in the driver for completeness.
 *   0 = Shut off PCI parity check
 *  -1 = Normal polarity pci parity checking
 *   1 = reverse polarity pci parity checking
 *
 * NOTE: you can't actually pass -1 on the lilo prompt.  So, to set this
 * variable to -1 you would actually want to simply pass the variable
 * name without a number.  That will invert the 0 which will result in
 * -1.
 */
static int aic79xx_pci_parity = 0;

/*
 * aic79xx_detect() has been run, so register all device arrivals
 * immediately with the system rather than deferring to the sorted
 * attachment performed by aic79xx_detect().
 */
int aic79xx_detect_complete;

/*
 * So that we can set how long each device is given as a selection timeout.
 * The table of values goes like this:
 *   0 - 256ms
 *   1 - 128ms
 *   2 - 64ms
 *   3 - 32ms
 * We default to 256ms because some older devices need a longer time
 * to respond to initial selection.
 */
static int aic79xx_seltime = 0x00;

/*
 * Certain devices do not perform any aging on commands.  Should the
 * device be saturated by commands in one portion of the disk, it is
 * possible for transactions on far away sectors to never be serviced.
 * To handle these devices, we can periodically send an ordered tag to
 * force all outstanding transactions to be serviced prior to a new
 * transaction.
 */
int aic79xx_periodic_otag;

/*
 * Module information and settable options.
 */
#ifdef MODULE
static char *aic79xx = NULL;
/*
 * Just in case someone uses commas to separate items on the insmod
 * command line, we define a dummy buffer here to avoid having insmod
 * write wild stuff into our code segment
 */
static char dummy_buffer[60] = "Please don't trounce on me insmod!!\n";

MODULE_AUTHOR("Maintainer: Justin T. Gibbs <gibbs@scsiguy.com>");
MODULE_DESCRIPTION("Adaptec Aic77XX/78XX SCSI Host Bus Adapter driver");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,10)
MODULE_LICENSE("Dual BSD/GPL");
#endif
MODULE_PARM(aic79xx, "s");
MODULE_PARM_DESC(aic79xx, "period delimited, options string.
	verbose			Enable verbose/diagnostic logging
	debug			Bitmask of debug values to enable
	no_reset		Supress initial bus resets
	extended		Enable extended geometry on all controllers
	periodic_otag		Send an ordered tagged transaction periodically
				to prevent tag starvation.  This may be
				required by some older disk drives/RAID arrays. 
	reverse_scan		Sort PCI devices highest Bus/Slot to lowest
	tag_info:<tag_str>	Set per-target tag depth
	rd_strm:<rd_strm_masks> Set per-target read streaming setting.
	seltime:<int>		Selection Timeout(0/256ms,1/128ms,2/64ms,3/32ms)

	Sample /etc/modules.conf line:
		Enable verbose logging
		Set tag depth on Controller 2/Target 2 to 10 tags
		Shorten the selection timeout to 128ms from its default of 256

	options aic79xx='\"verbose.tag_info:{{}.{}.{..10}}.seltime:1\"'

	Sample /etc/modules.conf line:
		Change Read Streaming for Controller's 2 and 3

	options aic79xx='\"rd_strm:{..0xFFF0.0xC0F0}\"'
");
#endif

static void ahd_linux_handle_scsi_status(struct ahd_softc *,
					 struct ahd_linux_device *,
					 struct scb *);
static void ahd_linux_filter_command(struct ahd_softc*, Scsi_Cmnd*,
				     struct scb*);
static void ahd_linux_dev_timed_unfreeze(u_long arg);
#if NO_YET
static void ahd_linux_sem_timeout(u_long arg);
static int  ahd_linux_queue_recovery_cmd(Scsi_Cmnd *cmd, scb_flag flag);
#endif 
static void ahd_linux_initialize_scsi_bus(struct ahd_softc *ahd);
static void ahd_linux_select_queue_depth(struct Scsi_Host *host,
					 Scsi_Device *scsi_devs);
static u_int ahd_linux_user_tagdepth(struct ahd_softc *ahd,
				     struct ahd_devinfo *devinfo);
static void ahd_linux_device_queue_depth(struct ahd_softc *ahd,
					 Scsi_Device *device);
static struct ahd_linux_target*	ahd_linux_alloc_target(struct ahd_softc*,
						       u_int, u_int);
static void			ahd_linux_free_target(struct ahd_softc*,
						      struct ahd_linux_target*);
static struct ahd_linux_device*	ahd_linux_alloc_device(struct ahd_softc*,
						       struct ahd_linux_target*,
						       u_int);
static void			ahd_linux_free_device(struct ahd_softc*,
						      struct ahd_linux_device*);
static void ahd_linux_run_device_queue(struct ahd_softc*,
				       struct ahd_linux_device*);
static void ahd_linux_setup_tag_info(char *p, char *end);
static void ahd_linux_setup_rd_strm_info(char *p, char *end);
static int ahd_linux_next_unit(void);
static void ahd_runq_tasklet(unsigned long data);
static int ahd_linux_halt(struct notifier_block *nb, u_long event, void *buf);

static __inline struct ahd_linux_device*
		     ahd_linux_get_device(struct ahd_softc *ahd, u_int channel,
					  u_int target, u_int lun, int alloc);
static __inline void ahd_linux_queue_cmd_complete(struct ahd_softc *ahd,
						  Scsi_Cmnd *cmd);
static __inline void ahd_linux_run_complete_queue(struct ahd_softc *ahd,
						  struct ahd_cmd *acmd);
static __inline void ahd_linux_check_device_queue(struct ahd_softc *ahd,
						  struct ahd_linux_device *dev);
static __inline struct ahd_linux_device *
		     ahd_linux_next_device_to_run(struct ahd_softc *ahd);
static __inline void ahd_linux_run_device_queues(struct ahd_softc *ahd);
static __inline void ahd_linux_sniff_command(struct ahd_softc*, Scsi_Cmnd*,
					     struct scb*);
static __inline void ahd_linux_unmap_scb(struct ahd_softc*, struct scb*);

static __inline int ahd_linux_map_seg(struct ahd_softc *ahd, struct scb *scb,
		 		      struct ahd_dma_seg *sg,
				      bus_addr_t addr, bus_size_t len);

static __inline struct ahd_linux_device*
ahd_linux_get_device(struct ahd_softc *ahd, u_int channel, u_int target,
	       u_int lun, int alloc)
{
	struct ahd_linux_target *targ;
	struct ahd_linux_device *dev;
	u_int target_offset;

	target_offset = target;
	if (channel != 0)
		target_offset += 8;
	targ = ahd->platform_data->targets[target_offset];
	if (targ == NULL) {
		if (alloc != 0) {
			targ = ahd_linux_alloc_target(ahd, channel, target);
			if (targ == NULL)
				return (NULL);
		} else
			return (NULL);
	}
	dev = targ->devices[lun];
	if (dev == NULL && alloc != 0)
		dev = ahd_linux_alloc_device(ahd, targ, lun);
	return (dev);
}

static __inline void
ahd_linux_queue_cmd_complete(struct ahd_softc *ahd, Scsi_Cmnd *cmd)
{
	/*
	 * Typically, the complete queue has very few entries
	 * queued to it before the queue is emptied by
	 * ahd_linux_run_complete_queue, so sorting the entries
	 * by generation number should be inexpensive.
	 * We perform the sort so that commands that complete
	 * with an error are retuned in the order origionally
	 * queued to the controller so that any subsequent retries
	 * are performed in order.  The underlying ahd routines do
	 * not guarantee the order that aborted commands will be
	 * returned to us.
	 */
	struct ahd_completeq *completeq;
	struct ahd_cmd *list_cmd;
	struct ahd_cmd *acmd;

	/*
	 * If we want the request requeued, make sure there
	 * are sufficent retries.  In the old scsi error code,
	 * we used to be able to specify a result code that
	 * bypassed the retry count.  Now we must use this
	 * hack.
	 */
	if (cmd->result == (CAM_REQUEUE_REQ << 16))
		cmd->retries--;
	completeq = &ahd->platform_data->completeq;
	list_cmd = TAILQ_FIRST(completeq);
	acmd = (struct ahd_cmd *)cmd;
	while (list_cmd != NULL
	    && acmd_scsi_cmd(list_cmd).serial_number
	     < acmd_scsi_cmd(acmd).serial_number)
		list_cmd = TAILQ_NEXT(list_cmd, acmd_links.tqe);
	if (list_cmd != NULL)
		TAILQ_INSERT_BEFORE(list_cmd, acmd, acmd_links.tqe);
	else
		TAILQ_INSERT_TAIL(completeq, acmd, acmd_links.tqe);
}

static __inline void
ahd_linux_run_complete_queue(struct ahd_softc *ahd, struct ahd_cmd *acmd)
{	
	u_long done_flags;

	ahd_done_lock(ahd, &done_flags);
	while (acmd != NULL) {
		Scsi_Cmnd *cmd;

		cmd = &acmd_scsi_cmd(acmd);
		acmd = TAILQ_NEXT(acmd, acmd_links.tqe);
		cmd->host_scribble = NULL;
		cmd->scsi_done(cmd);
	}
	ahd_done_unlock(ahd, &done_flags);
}

static __inline void
ahd_linux_check_device_queue(struct ahd_softc *ahd,
			     struct ahd_linux_device *dev)
{
	if ((dev->flags & AHD_DEV_FREEZE_TIL_EMPTY) != 0
	 && dev->active == 0) {
		dev->flags &= ~AHD_DEV_FREEZE_TIL_EMPTY;
		dev->qfrozen--;
	}

	if (TAILQ_FIRST(&dev->busyq) == NULL
	 || dev->openings == 0 || dev->qfrozen != 0)
		return;

	ahd_linux_run_device_queue(ahd, dev);
}

static __inline struct ahd_linux_device *
ahd_linux_next_device_to_run(struct ahd_softc *ahd)
{
	
	if ((ahd->flags & AHD_RESOURCE_SHORTAGE) != 0
	 || ahd->platform_data->qfrozen != 0)
		return (NULL);
	return (TAILQ_FIRST(&ahd->platform_data->device_runq));
}

static __inline void
ahd_linux_run_device_queues(struct ahd_softc *ahd)
{
	struct ahd_linux_device *dev;

	while ((dev = ahd_linux_next_device_to_run(ahd)) != NULL) {
		TAILQ_REMOVE(&ahd->platform_data->device_runq, dev, links);
		dev->flags &= ~AHD_DEV_ON_RUN_LIST;
		ahd_linux_check_device_queue(ahd, dev);
	}
}

static __inline void
ahd_linux_sniff_command(struct ahd_softc *ahd, Scsi_Cmnd *cmd, struct scb *scb)
{
	/*
	 * Determine whether we care to filter
	 * information out of this command.  If so,
	 * pass it on to ahd_linux_filter_command() for more
	 * heavy weight processing.
	 */
	if (cmd->cmnd[0] == INQUIRY)
		ahd_linux_filter_command(ahd, cmd, scb);
}

static __inline void
ahd_linux_unmap_scb(struct ahd_softc *ahd, struct scb *scb)
{
	Scsi_Cmnd *cmd;
	int direction;

	cmd = scb->io_ctx;
	direction = scsi_to_pci_dma_dir(cmd->sc_data_direction);
	ahd_sync_sglist(ahd, scb, BUS_DMASYNC_POSTWRITE);
	if (cmd->use_sg != 0) {
		struct scatterlist *sg;

		sg = (struct scatterlist *)cmd->request_buffer;
		pci_unmap_sg(ahd->dev_softc, sg, cmd->use_sg, direction);
	} else if (cmd->request_bufflen != 0) {
		pci_unmap_single(ahd->dev_softc,
				 scb->platform_data->buf_busaddr,
				 cmd->request_bufflen, direction);
	}
}

static __inline int
ahd_linux_map_seg(struct ahd_softc *ahd, struct scb *scb,
		  struct ahd_dma_seg *sg, bus_addr_t addr, bus_size_t len)
{
	int	 consumed;

	if ((scb->sg_count + 1) > AHD_NSEG)
		panic("Too few segs for dma mapping.  "
		      "Increase AHD_NSEG\n");

	consumed = 1;
	sg->addr = ahd_htole32(addr & 0xFFFFFFFF);
	scb->platform_data->xfer_len += len;
	if (sizeof(bus_addr_t) > 4
	 && (ahd->flags & AHD_39BIT_ADDRESSING) != 0) {
		/*
		 * Due to DAC restrictions, we can't
		 * cross a 4GB boundary.
		 */
		if ((addr ^ (addr + len - 1)) & ~0xFFFFFFFF) {
			struct	 ahd_dma_seg *next_sg;
			uint32_t next_len;

			printf("Crossed Seg\n");
			if ((scb->sg_count + 2) > AHD_NSEG)
				panic("Too few segs for dma mapping.  "
				      "Increase AHD_NSEG\n");

			consumed++;
			next_sg = sg + 1;
			next_sg->addr = 0;
			next_len = 0x100000000 - (addr & 0xFFFFFFFF);
			len -= next_len;
			next_len |= ((addr >> 8) + 0x1000000) & 0x7F000000;
			next_sg->len = ahd_htole32(next_len);
		}
		len |= (addr >> 8) & 0x7F000000;
	}
	sg->len = ahd_htole32(len);
	return (consumed);
}

/**************************** Tasklet Handler *********************************/

static void
ahd_runq_tasklet(unsigned long data)
{
	struct ahd_softc* ahd;
	struct ahd_linux_device *dev;
	u_long flags;

	ahd = (struct ahd_softc *)data;
	ahd_lock(ahd, &flags);
	while ((dev = ahd_linux_next_device_to_run(ahd)) != NULL) {
	
		TAILQ_REMOVE(&ahd->platform_data->device_runq, dev, links);
		dev->flags &= ~AHD_DEV_ON_RUN_LIST;
		ahd_linux_check_device_queue(ahd, dev);
		/* Yeild to our interrupt handler */
		ahd_unlock(ahd, &flags);
		ahd_lock(ahd, &flags);
	}
	ahd_unlock(ahd, &flags);
}

/************************ Shutdown/halt/reboot hook ***************************/
#include <linux/notifier.h>
#include <linux/reboot.h>

static struct notifier_block ahd_linux_notifier = {
	ahd_linux_halt, NULL, 0
};

static int ahd_linux_halt(struct notifier_block *nb, u_long event, void *buf)
{
	struct ahd_softc *ahd;

	if (event == SYS_DOWN || event == SYS_HALT) {
		TAILQ_FOREACH(ahd, &ahd_tailq, links) {
			ahd_shutdown(ahd);
		}
	}
	return (NOTIFY_OK);
}

/******************************** Macros **************************************/
#define BUILD_SCSIID(ahd, cmd)						\
	((((cmd)->target << TID_SHIFT) & TID) | (ahd)->our_id)

/******************************** Bus DMA *************************************/
int
ahd_dma_tag_create(struct ahd_softc *ahd, bus_dma_tag_t parent,
		   bus_size_t alignment, bus_size_t boundary,
		   bus_addr_t lowaddr, bus_addr_t highaddr,
		   bus_dma_filter_t *filter, void *filterarg,
		   bus_size_t maxsize, int nsegments,
		   bus_size_t maxsegsz, int flags, bus_dma_tag_t *ret_tag)
{
	bus_dma_tag_t dmat;

	dmat = malloc(sizeof(*dmat), M_DEVBUF, M_NOWAIT);
	if (dmat == NULL)
		return (ENOMEM);

	/*
	 * Linux is very simplistic about DMA memory.  For now don't
	 * maintain all specification information.  Once Linux supplies
	 * better facilities for doing these operations, or the
	 * needs of this particular driver change, we might need to do
	 * more here.
	 */
	dmat->alignment = alignment;
	dmat->boundary = boundary;
	dmat->maxsize = maxsize;
	*ret_tag = dmat;
	return (0);
}

void
ahd_dma_tag_destroy(struct ahd_softc *ahd, bus_dma_tag_t dmat)
{
	free(dmat, M_DEVBUF);
}

int
ahd_dmamem_alloc(struct ahd_softc *ahd, bus_dma_tag_t dmat, void** vaddr,
		 int flags, bus_dmamap_t *mapp)
{
	bus_dmamap_t map;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	map = malloc(sizeof(*map), M_DEVBUF, M_NOWAIT);
	if (map == NULL)
		return (ENOMEM);
	/*
	 * Although we can dma data above 4GB, our
	 * "consistent" memory is below 4GB for
	 * space efficiency reasons (only need a 4byte
	 * address).  For this reason, we have to reset
	 * our dma mask when doing allocations.
	 */
	if (ahd->dev_softc != NULL)
		ahd_pci_set_dma_mask(ahd->dev_softc, 0xFFFFFFFF);
	*vaddr = pci_alloc_consistent(ahd->dev_softc,
				      dmat->maxsize, &map->bus_addr);
	if (ahd->dev_softc != NULL)
		ahd_pci_set_dma_mask(ahd->dev_softc,
				     ahd->platform_data->hw_dma_mask);
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,3,0) */
	/*
	 * At least in 2.2.14, malloc is a slab allocator so all
	 * allocations are aligned.  We assume for these kernel versions
	 * that all allocations will be bellow 4Gig, physically contiguous,
	 * and accessable via DMA by the controller.
	 */
	map = NULL; /* No additional information to store */
	*vaddr = malloc(dmat->maxsize, M_DEVBUF, M_NOWAIT);
#endif
	if (*vaddr == NULL)
		return (ENOMEM);
	*mapp = map;
	return(0);
}

void
ahd_dmamem_free(struct ahd_softc *ahd, bus_dma_tag_t dmat,
		void* vaddr, bus_dmamap_t map)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	pci_free_consistent(ahd->dev_softc, dmat->maxsize,
			    vaddr, map->bus_addr);
#else
	free(vaddr, M_DEVBUF);
#endif
}

int
ahd_dmamap_load(struct ahd_softc *ahd, bus_dma_tag_t dmat, bus_dmamap_t map,
		void *buf, bus_size_t buflen, bus_dmamap_callback_t *cb,
		void *cb_arg, int flags)
{
	/*
	 * Assume for now that this will only be used during
	 * initialization and not for per-transaction buffer mapping.
	 */
	bus_dma_segment_t stack_sg;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	stack_sg.ds_addr = map->bus_addr;
#else
#define VIRT_TO_BUS(a) (uint32_t)virt_to_bus((void *)(a))
	stack_sg.ds_addr = VIRT_TO_BUS(buf);
#endif
	stack_sg.ds_len = dmat->maxsize;
	cb(cb_arg, &stack_sg, /*nseg*/1, /*error*/0);
	return (0);
}

void
ahd_dmamap_destroy(struct ahd_softc *ahd, bus_dma_tag_t dmat, bus_dmamap_t map)
{
	/*
	 * The map may is NULL in our < 2.3.X implementation.
	 */
	if (map != NULL)
		free(map, M_DEVBUF);
}

int
ahd_dmamap_unload(struct ahd_softc *ahd, bus_dma_tag_t dmat, bus_dmamap_t map)
{
	/* Nothing to do */
	return (0);
}

/********************* Platform Dependent Functions ***************************/
int
ahd_softc_comp(struct ahd_softc *lahd, struct ahd_softc *rahd)
{
	int	value;
	char	primary_channel;

	/*
	 * Under Linux, cards are ordered as follows:
	 *	1) PCI devices with BIOS enabled sorted by bus/slot/func.
	 *	2) All remaining PCI devices sorted by bus/slot/func.
	 */
	value = (lahd->flags & AHD_BIOS_ENABLED)
	      - (rahd->flags & AHD_BIOS_ENABLED);
	if (value != 0)
		/* Controllers with BIOS enabled have a *higher* priority */
		return (-value);

	/* Still equal.  Sort by bus/slot/func. */
	if (aic79xx_reverse_scan != 0)
		value = ahd_get_pci_bus(rahd->dev_softc)
		      - ahd_get_pci_bus(lahd->dev_softc);
	else
		value = ahd_get_pci_bus(lahd->dev_softc)
		      - ahd_get_pci_bus(rahd->dev_softc);
	if (value != 0)
		return (value);
	if (aic79xx_reverse_scan != 0)
		value = ahd_get_pci_slot(rahd->dev_softc)
		      - ahd_get_pci_slot(lahd->dev_softc);
	else
		value = ahd_get_pci_slot(lahd->dev_softc)
		      - ahd_get_pci_slot(rahd->dev_softc);
	if (value != 0)
		return (value);

	/*
	 * On multi-function devices, the user can choose
	 * to have function 1 probed before function 0.
	 * Give whichever channel is the primary channel
	 * the lowest priority.
	 */
	primary_channel = (lahd->flags & AHD_PRIMARY_CHANNEL) + 'A';
	value = 1;
	if (lahd->channel == primary_channel)
		value = -1;
	return (value);
}

static void
ahd_linux_setup_tag_info(char *p, char *end)
{
	char	*base;
	char	*tok;
	char	*tok_end;
	char	*tok_end2;
	int      i;
	int      instance;
	int	 targ;
	int	 done;
	char	 tok_list[] = {'.', ',', '{', '}', '\0'};

	if (*p != ':')
		return;

	instance = -1;
	targ = -1;
	done = FALSE;
	base = p;
	/* Forward us just past the ':' */
	tok = base + 1;
	tok_end = strchr(tok, '\0');
	if (tok_end < end)
		*tok_end = ',';
	while (!done) {
		switch (*tok) {
		case '{':
			if (instance == -1)
				instance = 0;
			else if (targ == -1)
				targ = 0;
			tok++;
			break;
		case '}':
			if (targ != -1)
				targ = -1;
			else if (instance != -1)
				instance = -1;
			tok++;
			break;
		case ',':
		case '.':
			if (instance == -1)
				done = TRUE;
			else if (targ >= 0)
				targ++;
			else if (instance >= 0)
				instance++;
			if ((targ >= AHD_NUM_TARGETS) ||
			    (instance >= NUM_ELEMENTS(aic79xx_tag_info)))
				done = TRUE;
			tok++;
			if (!done) {
				base = tok;
			}
			break;
		case '\0':
			done = TRUE;
			break;
		default:
			done = TRUE;
			tok_end = strchr(tok, '\0');
			for (i = 0; tok_list[i]; i++) {
				tok_end2 = strchr(tok, tok_list[i]);
				if ((tok_end2) && (tok_end2 < tok_end)) {
					tok_end = tok_end2;
					done = FALSE;
				}
			}
			if ((instance >= 0) && (targ >= 0)
			 && (instance < NUM_ELEMENTS(aic79xx_tag_info))
			 && (targ < AHD_NUM_TARGETS)) {
				aic79xx_tag_info[instance].tag_commands[targ] =
				    simple_strtoul(tok, NULL, 0) & 0xff;
			}
			tok = tok_end;
			break;
		}
	}
	while ((p != base) && (p != NULL))
		p = strtok(NULL, ",.");
}

static void
ahd_linux_setup_rd_strm_info(char *p, char *end)
{
	char	*base;
	char	*tok;
	char	*tok_end;
	char	*tok_end2;
	int      i;
	int      instance;
	int	 targ;
	int	 done;
	char	 tok_list[] = {'.', ',', '{', '}', '\0'};

	if (*p != ':')
		return;

	instance = -1;
	targ = -1;
	done = FALSE;
	base = p;
	/* Forward us just past the ':' */
	tok = base + 1;
	tok_end = strchr(tok, '\0');
	if (tok_end < end)
		*tok_end = ',';
	while (!done) {
		switch (*tok) {
		case '{':
			if (instance == -1)
				instance = 0;
			tok++;
			break;
		case '}':
			if (instance != -1)
				instance = -1;
			tok++;
			break;
		case ',':
		case '.':
			if (instance == -1)
				done = TRUE;
			else if (instance >= 0)
				instance++;
			if (instance >= NUM_ELEMENTS(aic79xx_rd_strm_info))
				done = TRUE;
			tok++;
			if (!done) {
				base = tok;
			}
			break;
		case '\0':
			done = TRUE;
			break;
		default:
			done = TRUE;
			tok_end = strchr(tok, '\0');
			for (i = 0; tok_list[i]; i++) {
				tok_end2 = strchr(tok, tok_list[i]);
				if ((tok_end2) && (tok_end2 < tok_end)) {
					tok_end = tok_end2;
					done = FALSE;
				}
			}
			if ((instance >= 0)
			 && (instance < NUM_ELEMENTS(aic79xx_tag_info))) {
				aic79xx_rd_strm_info[instance] =
				    simple_strtoul(tok, NULL, 0) & 0xffff;
			}
			tok = tok_end;
			break;
		}
	}
	while ((p != base) && (p != NULL))
		p = strtok(NULL, ",.");
}

/*
 * Handle Linux boot parameters. This routine allows for assigning a value
 * to a parameter with a ':' between the parameter and the value.
 * ie. aic79xx=stpwlev:1,extended
 */
int
aic79xx_setup(char *s)
{
	int	i, n;
	char   *p;
	char   *end;

	static struct {
		const char *name;
		uint32_t *flag;
	} options[] = {
		{ "extended", &aic79xx_extended },
		{ "no_reset", &aic79xx_no_reset },
		{ "verbose", &aic79xx_verbose },
#ifdef AHD_DEBUG
		{ "debug", &ahd_debug },
#endif
		{ "reverse_scan", &aic79xx_reverse_scan },
		{ "periodic_otag", &aic79xx_periodic_otag },
		{ "pci_parity", &aic79xx_pci_parity },
		{ "seltime", &aic79xx_seltime },
		{ "tag_info", NULL },
		{ "rd_strm", NULL }
	};

	end = strchr(s, '\0');

	for (p = strtok(s, ",."); p; p = strtok(NULL, ",.")) {
		for (i = 0; i < NUM_ELEMENTS(options); i++) {
			n = strlen(options[i].name);

			if (strncmp(options[i].name, p, n) != 0)
				continue;

			if (strncmp(p, "tag_info", n) == 0) {
				ahd_linux_setup_tag_info(p + n, end);
			} else if (strncmp(p, "rd_strm", n) == 0) {
				ahd_linux_setup_rd_strm_info(p + n, end);
			} else if (p[n] == ':') {
				*(options[i].flag) =
				    simple_strtoul(p + n + 1, NULL, 0);
			} else if (!strncmp(p, "verbose", n)) {
				*(options[i].flag) = 1;
			} else {
				*(options[i].flag) = ~(*(options[i].flag));
			}
			break;
		}
	}
	return 1;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
__setup("aic79xx=", aic79xx_setup);
#endif

int aic79xx_verbose;

/*
 * Try to detect an Adaptec 79XX controller.
 */
int
ahd_linux_detect(Scsi_Host_Template *template)
{
	struct	ahd_softc *ahd;
	int     found;

	/*
	 * It is a bug that the upper layer takes
	 * this lock just prior to calling us.
	 */
	spin_unlock_irq(&io_request_lock);

	/*
	 * Sanity checking of Linux SCSI data structures so
	 * that some of our hacks^H^H^H^H^Hassumptions aren't
	 * violated.
	 */
	if (offsetof(struct ahd_cmd_internal, end)
	  > offsetof(struct scsi_cmnd, host_scribble)) {
		printf("ahd_linux_detect: SCSI data structures changed.\n");
		printf("ahd_linux_detect: Unable to attach\n");
		return (0);
	}
#ifdef MODULE
	/*
	 * If we've been passed any parameters, process them now.
	 */
	if (aic79xx)
		aic79xx_setup(aic79xx);
	if (dummy_buffer[0] != 'P')
		printk(KERN_WARNING
"aic79xx: Please read the file /usr/src/linux/drivers/scsi/README.aic79xx\n"
"aic79xx: to see the proper way to specify options to the aic79xx module\n"
"aic79xx: Specifically, don't use any commas when passing arguments to\n"
"aic79xx: insmod or else it might trash certain memory areas.\n");
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
	template->proc_name = "aic79xx";
#else
	template->proc_dir = &proc_scsi_aic79xx;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,7)
	/*
	 * We can only map 16MB per-SG
	 * so create a sector limit of
	 * "16MB" in 2K sectors.
	 */
	template->max_sectors = 8192;
#endif

	/*
	 * Initialize our softc list lock prior to
	 * probing for any adapters.
	 */
	ahd_list_lockinit();

#ifdef CONFIG_PCI
	ahd_linux_pci_probe(template);
#endif

	/*
	 * Register with the SCSI layer all
	 * controllers we've found.
	 */
	spin_lock_irq(&io_request_lock);
	found = 0;
	TAILQ_FOREACH(ahd, &ahd_tailq, links) {

		if (ahd_linux_register_host(ahd, template) == 0)
			found++;
	}
	aic79xx_detect_complete++;
	return (found);
}

int
ahd_linux_register_host(struct ahd_softc *ahd, Scsi_Host_Template *template)
{
	char  buf[80];
	struct Scsi_Host *host;
	char *new_name;
	u_long s;

	template->name = ahd->description;
	host = scsi_register(template, sizeof(struct ahd_softc *));
	if (host == NULL)
		return (ENOMEM);

	ahd_lock(ahd, &s);
	*((struct ahd_softc **)host->hostdata) = ahd;
	ahd->platform_data->host = host;
	host->can_queue = AHD_MAX_QUEUE;
	host->cmd_per_lun = 2;
	host->sg_tablesize = AHD_NSEG;
	host->select_queue_depths = ahd_linux_select_queue_depth;
	host->this_id = ahd->our_id;
	host->irq = ahd->platform_data->irq;
	host->max_id = (ahd->features & AHD_WIDE) ? 16 : 8;
	host->max_lun = AHD_NUM_LUNS;
	host->max_channel = 0;
	ahd_set_unit(ahd, ahd_linux_next_unit());
	sprintf(buf, "scsi%d", host->host_no);
	new_name = malloc(strlen(buf) + 1, M_DEVBUF, M_NOWAIT);
	if (new_name != NULL) {
		strcpy(new_name, buf);
		ahd_set_name(ahd, new_name);
	}
	host->unique_id = ahd->unit;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4)
	scsi_set_pci_device(host, ahd->dev_softc);
#endif
	ahd_linux_initialize_scsi_bus(ahd);
	ahd_unlock(ahd, &s);
	return (0);
}

uint64_t
ahd_linux_get_memsize()
{
	struct sysinfo si;

	si_meminfo(&si);
	return (si.totalram << PAGE_SHIFT);
}

/*
 * Find the smallest available unit number to use
 * for a new device.  We don't just use a static
 * count to handle the "repeated hot-(un)plug"
 * scenario.
 */
static int
ahd_linux_next_unit()
{
	struct ahd_softc *ahd;
	int unit;

	unit = 0;
retry:
	TAILQ_FOREACH(ahd, &ahd_tailq, links) {
		if (ahd->unit == unit) {
			unit++;
			goto retry;
		}
	}
	return (unit);
}

/*
 * Place the SCSI bus into a known state by either resetting it,
 * or forcing transfer negotiations on the next command to any
 * target.
 */
void
ahd_linux_initialize_scsi_bus(struct ahd_softc *ahd)
{
	int i;
	int numtarg;

	i = 0;
	numtarg = 0;

	if (aic79xx_no_reset != 0)
		ahd->flags &= ~AHD_RESET_BUS_A;

	if ((ahd->flags & AHD_RESET_BUS_A) != 0)
		ahd_reset_channel(ahd, 'A', /*initiate_reset*/TRUE);
	else
		numtarg = (ahd->features & AHD_WIDE) ? 16 : 8;

	for (; i < numtarg; i++) {
		struct ahd_devinfo devinfo;
		struct ahd_initiator_tinfo *tinfo;
		struct ahd_tmode_tstate *tstate;
		u_int our_id;
		u_int target_id;
		char channel;

		channel = 'A';
		our_id = ahd->our_id;
		target_id = i;
		tinfo = ahd_fetch_transinfo(ahd, channel, our_id,
					    target_id, &tstate);
		tinfo->goal = tinfo->user;
		/*
		 * Don't try negotiations that require PPR messages
		 * until we successfully retrieve Inquiry data.
		 */
		tinfo->goal.ppr_options = 0;
		if (tinfo->goal.transport_version > SCSI_REV_2)
			tinfo->goal.transport_version = SCSI_REV_2;
		ahd_compile_devinfo(&devinfo, our_id, target_id,
				   CAM_LUN_WILDCARD, channel, ROLE_INITIATOR);
		ahd_update_neg_request(ahd, &devinfo, tstate,
				       tinfo, /*force*/FALSE);
	}
	/* Give the bus some time to recover */
	if ((ahd->flags & AHD_RESET_BUS_A) != 0) {
		ahd_freeze_simq(ahd);
		init_timer(&ahd->platform_data->reset_timer);
		ahd->platform_data->reset_timer.data = (u_long)ahd;
		ahd->platform_data->reset_timer.expires =
		    jiffies + (AIC79XX_RESET_DELAY * HZ)/1000;
		ahd->platform_data->reset_timer.function =
		    (ahd_linux_callback_t *)ahd_release_simq;
		add_timer(&ahd->platform_data->reset_timer);
	}
}

int
ahd_platform_alloc(struct ahd_softc *ahd, void *platform_arg)
{
	ahd->platform_data =
	    malloc(sizeof(struct ahd_platform_data), M_DEVBUF, M_NOWAIT);
	if (ahd->platform_data == NULL)
		return (ENOMEM);
	memset(ahd->platform_data, 0, sizeof(struct ahd_platform_data));
	TAILQ_INIT(&ahd->platform_data->completeq);
	TAILQ_INIT(&ahd->platform_data->device_runq);
	ahd->platform_data->irq = AHD_LINUX_NOIRQ;
	ahd->platform_data->hw_dma_mask = 0xFFFFFFFF;
	ahd_lockinit(ahd);
	ahd_done_lockinit(ahd);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	init_MUTEX_LOCKED(&ahd->platform_data->eh_sem);
#else
	ahd->platform_data->eh_sem = MUTEX_LOCKED;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	tasklet_init(&ahd->platform_data->runq_tasklet, ahd_runq_tasklet,
		     (unsigned long)ahd);
#endif
	ahd->seltime = (aic79xx_seltime & 0x3) << 4;
	
	if (TAILQ_EMPTY(&ahd_tailq))
		register_reboot_notifier(&ahd_linux_notifier);
	return (0);
}

void
ahd_platform_free(struct ahd_softc *ahd)
{
	if (ahd->platform_data != NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		tasklet_kill(&ahd->platform_data->runq_tasklet);
#endif
		if (ahd->platform_data->host != NULL)
			scsi_unregister(ahd->platform_data->host);
		if (ahd->platform_data->irq != AHD_LINUX_NOIRQ)
			free_irq(ahd->platform_data->irq, ahd);
		if (ahd->tags[0] == BUS_SPACE_PIO
		 && ahd->bshs[0].ioport != 0)
			release_region(ahd->bshs[0].ioport, 256);
		if (ahd->tags[1] == BUS_SPACE_PIO
		 && ahd->bshs[1].ioport != 0)
			release_region(ahd->bshs[1].ioport, 256);
		if (ahd->tags[0] == BUS_SPACE_MEMIO
		 && ahd->bshs[0].maddr != NULL) {
			u_long base_addr;

			base_addr = (u_long)ahd->bshs[0].maddr;
			base_addr &= PAGE_MASK;
			iounmap((void *)base_addr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
			release_mem_region(ahd->platform_data->mem_busaddr,
					   0x1000);
#endif
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		/* XXX Need an instance detach in the PCI code */
		if (ahd->dev_softc != NULL)
			ahd->dev_softc->driver = NULL;
#endif
		free(ahd->platform_data, M_DEVBUF);
	}
	if (TAILQ_EMPTY(&ahd_tailq)) {
		unregister_reboot_notifier(&ahd_linux_notifier);
#ifdef CONFIG_PCI
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		pci_unregister_driver(&aic79xx_pci_driver);
#endif
#endif
	}
}

void
ahd_platform_freeze_devq(struct ahd_softc *ahd, struct scb *scb)
{
	ahd_platform_abort_scbs(ahd, SCB_GET_TARGET(ahd, scb),
				SCB_GET_CHANNEL(ahd, scb),
				SCB_GET_LUN(scb), SCB_LIST_NULL,
				ROLE_UNKNOWN, CAM_REQUEUE_REQ);
}

void
ahd_platform_set_tags(struct ahd_softc *ahd, struct ahd_devinfo *devinfo,
		      ahd_queue_alg alg)
{
	struct ahd_linux_device *dev;
	int was_queuing;
	int now_queuing;

	dev = ahd_linux_get_device(ahd, devinfo->channel - 'A',
				   devinfo->target,
				   devinfo->lun, /*alloc*/FALSE);
	if (dev == NULL)
		return;
	was_queuing = dev->flags & (AHD_DEV_Q_BASIC|AHD_DEV_Q_TAGGED);
	now_queuing = alg != AHD_QUEUE_NONE;
	if ((dev->flags & AHD_DEV_FREEZE_TIL_EMPTY) == 0
	 && (was_queuing != now_queuing)
	 && (dev->active != 0)) {
		dev->flags |= AHD_DEV_FREEZE_TIL_EMPTY;
		dev->qfrozen++;
	}

	dev->flags &= ~(AHD_DEV_Q_BASIC|AHD_DEV_Q_TAGGED|AHD_DEV_PERIODIC_OTAG);
	if (now_queuing) {
		u_int usertags;

		usertags = ahd_linux_user_tagdepth(ahd, devinfo);
		if (!was_queuing) {
			/*
			 * Start out agressively and allow our
			 * dynamic queue depth algorithm to take
			 * care of the rest.
			 */
			dev->maxtags = usertags;
			dev->openings = dev->maxtags - dev->active;
		}
		if (alg == AHD_QUEUE_TAGGED) {
			dev->flags |= AHD_DEV_Q_TAGGED;
			if (aic79xx_periodic_otag != 0)
				dev->flags |= AHD_DEV_PERIODIC_OTAG;
		} else
			dev->flags |= AHD_DEV_Q_BASIC;
	} else {
		/* We can only have one opening. */
		dev->maxtags = 0;
		dev->openings =  1 - dev->active;
	}
}

int
ahd_platform_abort_scbs(struct ahd_softc *ahd, int target, char channel,
			int lun, u_int tag, role_t role, uint32_t status)
{
	int targ;
	int maxtarg;
	int maxlun;
	int clun;
	int count;

	if (tag != SCB_LIST_NULL)
		return (0);

	targ = 0;
	if (target != CAM_TARGET_WILDCARD) {
		targ = target;
		maxtarg = targ + 1;
	} else {
		maxtarg = (ahd->features & AHD_WIDE) ? 16 : 8;
	}
	clun = 0;
	if (lun != CAM_LUN_WILDCARD) {
		clun = lun;
		maxlun = clun + 1;
	} else {
		maxlun = AHD_NUM_LUNS;
	}

	count = 0;
	for (; targ < maxtarg; targ++) {

		for (; clun < maxlun; clun++) {
			struct ahd_linux_device *dev;
			struct ahd_busyq *busyq;
			struct ahd_cmd *acmd;

			dev = ahd_linux_get_device(ahd, /*chan*/0, targ,
						   clun, /*alloc*/FALSE);
			if (dev == NULL)
				continue;

			busyq = &dev->busyq;
			while ((acmd = TAILQ_FIRST(busyq)) != NULL) {
				Scsi_Cmnd *cmd;

				cmd = &acmd_scsi_cmd(acmd);
				TAILQ_REMOVE(busyq, acmd,
					     acmd_links.tqe);
				count++;
				cmd->result = status << 16;
				ahd_linux_queue_cmd_complete(ahd, cmd);
			}
		}
	}

	return (count);
}

/*
 * Sets the queue depth for each SCSI device hanging
 * off the input host adapter.
 */
static void
ahd_linux_select_queue_depth(struct Scsi_Host * host,
			     Scsi_Device * scsi_devs)
{
	Scsi_Device *device;
	struct	ahd_softc *ahd;
	u_long	flags;
	int	scbnum;

	ahd = *((struct ahd_softc **)host->hostdata);
	ahd_lock(ahd, &flags);
	scbnum = 0;
	for (device = scsi_devs; device != NULL; device = device->next) {
		if (device->host == host) {
			ahd_linux_device_queue_depth(ahd, device);
			scbnum += device->queue_depth;
		}
	}
	ahd_unlock(ahd, &flags);
}

static u_int
ahd_linux_user_tagdepth(struct ahd_softc *ahd, struct ahd_devinfo *devinfo)
{
	static int warned_user;
	u_int tags;

	tags = 0;
	if ((ahd->user_discenable & devinfo->target_mask) != 0) {
		if (warned_user == 0
		 && ahd->unit >= NUM_ELEMENTS(aic79xx_tag_info)) {

			printf("aic79xx: WARNING, insufficient "
			       "tag_info instances for installed "
			       "controllers. Using defaults\n");
			printf("aic79xx: Please update the "
			       "aic79xx_tag_info array in the "
			       "aic79xx.c source file.\n");
			tags = AHD_MAX_QUEUE;
			warned_user++;
		} else {
			adapter_tag_info_t *tag_info;

			tag_info = &aic79xx_tag_info[ahd->unit];
			tags = tag_info->tag_commands[devinfo->target_offset];
			if (tags > AHD_MAX_QUEUE)
				tags = AHD_MAX_QUEUE;
		}
	}
	return (tags);
}

/*
 * Determines the queue depth for a given device.
 */
static void
ahd_linux_device_queue_depth(struct ahd_softc *ahd, Scsi_Device * device)
{
	struct	ahd_devinfo devinfo;
	u_int	tags;

	ahd_compile_devinfo(&devinfo,
			    ahd->our_id,
			    device->id, device->lun,
			    device->channel == 0 ? 'A' : 'B',
			    ROLE_INITIATOR);
	tags = ahd_linux_user_tagdepth(ahd, &devinfo);
	if (tags != 0
	 && device->tagged_supported != 0) {

		device->queue_depth = tags;
		ahd_set_tags(ahd, &devinfo, AHD_QUEUE_TAGGED);
		printf("scsi%d:%c:%d:%d: Tagged Queuing enabled.  Depth %d\n",
	       	       ahd->platform_data->host->host_no, devinfo.channel,
		       devinfo.target, devinfo.lun, tags);
	} else {
		/*
		 * We allow the OS to queue 2 untagged transactions to
		 * us at any time even though we can only execute them
		 * serially on the controller/device.  This should remove
		 * some latency.
		 */
		device->queue_depth = 2;
	}
}

/*
 * Queue an SCB to the controller.
 */
int
ahd_linux_queue(Scsi_Cmnd * cmd, void (*scsi_done) (Scsi_Cmnd *))
{
	struct	 ahd_softc *ahd;
	struct	 ahd_linux_device *dev;
	u_long	 flags;

	ahd = *(struct ahd_softc **)cmd->host->hostdata;

	/*
	 * Save the callback on completion function.
	 */
	cmd->scsi_done = scsi_done;

	ahd_lock(ahd, &flags);
	dev = ahd_linux_get_device(ahd, cmd->channel, cmd->target,
				   cmd->lun, /*alloc*/TRUE);
	if (dev == NULL) {
		ahd_unlock(ahd, &flags);
		printf("aic79xx_linux_queue: Unable to allocate device!\n");
		return (-ENOMEM);
	}
	if (cmd->cmd_len > MAX_CDB_LEN)
		return (-EINVAL);
	cmd->result = CAM_REQ_INPROG << 16;
	TAILQ_INSERT_TAIL(&dev->busyq, (struct ahd_cmd *)cmd, acmd_links.tqe);
	if ((dev->flags & AHD_DEV_ON_RUN_LIST) == 0) {
		TAILQ_INSERT_TAIL(&ahd->platform_data->device_runq, dev, links);
		dev->flags |= AHD_DEV_ON_RUN_LIST;
		ahd_linux_run_device_queues(ahd);
	}
	ahd_unlock(ahd, &flags);
	return (0);
}

static void
ahd_linux_run_device_queue(struct ahd_softc *ahd, struct ahd_linux_device *dev)
{
	struct	 ahd_cmd *acmd;
	struct	 scsi_cmnd *cmd;
	struct	 scb *scb;
	struct	 hardware_scb *hscb;
	struct	 ahd_initiator_tinfo *tinfo;
	struct	 ahd_tmode_tstate *tstate;
	uint16_t mask;

	if ((dev->flags & AHD_DEV_ON_RUN_LIST) != 0)
		panic("running device on run list");

	while ((acmd = TAILQ_FIRST(&dev->busyq)) != NULL
	    && dev->openings > 0 && dev->qfrozen == 0) {

		/*
		 * Schedule us to run later.  The only reason we are not
		 * running is because the whole controller Q is frozen.
		 */
		if (ahd->platform_data->qfrozen != 0) {

			TAILQ_INSERT_TAIL(&ahd->platform_data->device_runq,
					  dev, links);
			dev->flags |= AHD_DEV_ON_RUN_LIST;
			return;
		}
		/*
		 * Get an scb to use.
		 */
		if ((scb = ahd_get_scb(ahd)) == NULL) {
			TAILQ_INSERT_TAIL(&ahd->platform_data->device_runq,
					 dev, links);
			dev->flags |= AHD_DEV_ON_RUN_LIST;
			ahd->flags |= AHD_RESOURCE_SHORTAGE;
			return;
		}
		TAILQ_REMOVE(&dev->busyq, acmd, acmd_links.tqe);
		cmd = &acmd_scsi_cmd(acmd);
		scb->io_ctx = cmd;
		scb->platform_data->dev = dev;
		hscb = scb->hscb;
		cmd->host_scribble = (char *)scb;

		/*
		 * Fill out basics of the HSCB.
		 */
		hscb->control = 0;
		hscb->scsiid = BUILD_SCSIID(ahd, cmd);
		hscb->lun = cmd->lun;
		mask = SCB_GET_TARGET_MASK(ahd, scb);
		tinfo = ahd_fetch_transinfo(ahd, SCB_GET_CHANNEL(ahd, scb),
					    SCB_GET_OUR_ID(scb),
					    SCB_GET_TARGET(ahd, scb), &tstate);

		if ((ahd->user_discenable & mask) != 0)
			hscb->control |= DISCENB;

		if ((tinfo->curr.ppr_options & MSG_EXT_PPR_IU_REQ) != 0)
			scb->flags |= SCB_PACKETIZED;

		if ((tstate->auto_negotiate & mask) != 0) {
			scb->flags |= SCB_AUTO_NEGOTIATE;
			scb->hscb->control |= MK_MESSAGE;
		}

		if ((dev->flags & (AHD_DEV_Q_TAGGED|AHD_DEV_Q_BASIC)) != 0) {
			if (dev->commands_since_idle_or_otag == AHD_OTAG_THRESH
			 && (dev->flags & AHD_DEV_Q_TAGGED) != 0) {
				hscb->control |= MSG_ORDERED_TASK;
				dev->commands_since_idle_or_otag = 0;
			} else {
				hscb->control |= MSG_SIMPLE_TASK;
			}
		}

		hscb->cdb_len = cmd->cmd_len;
		memcpy(hscb->shared_data.idata.cdb, cmd->cmnd, hscb->cdb_len);

		scb->sg_count = 0;
		ahd_set_residual(scb, 0);
		ahd_set_sense_residual(scb, 0);
		if (cmd->use_sg != 0) {
			void	*sg;
			struct	 scatterlist *cur_seg;
			u_int	 nseg;
			int	 dir;

			cur_seg = (struct scatterlist *)cmd->request_buffer;
			dir = scsi_to_pci_dma_dir(cmd->sc_data_direction);
			nseg = pci_map_sg(ahd->dev_softc, cur_seg,
					  cmd->use_sg, dir);
			scb->platform_data->xfer_len = 0;
			for (sg = scb->sg_list; nseg > 0; nseg--, cur_seg++) {
				bus_addr_t addr;
				bus_size_t len;

				addr = sg_dma_address(cur_seg);
				len = sg_dma_len(cur_seg);
				scb->platform_data->xfer_len += len;
				sg = ahd_sg_setup(ahd, scb, sg, addr, len,
						  /*last*/nseg == 1);
			}
		} else if (cmd->request_bufflen != 0) {
			void *sg;
			bus_addr_t addr;
			int dir;

			sg = scb->sg_list;
			dir = scsi_to_pci_dma_dir(cmd->sc_data_direction);
			addr = pci_map_single(ahd->dev_softc,
					      cmd->request_buffer,
					      cmd->request_bufflen, dir);
			scb->platform_data->xfer_len = cmd->request_bufflen;
			scb->platform_data->buf_busaddr = addr;
			sg = ahd_sg_setup(ahd, scb, sg, addr,
					  cmd->request_bufflen, /*last*/TRUE);
		}

		LIST_INSERT_HEAD(&ahd->pending_scbs, scb, pending_links);
		dev->openings--;
		dev->active++;
		dev->commands_issued++;
		if ((dev->flags & AHD_DEV_PERIODIC_OTAG) != 0)
			dev->commands_since_idle_or_otag++;
		scb->flags |= SCB_ACTIVE;
		ahd_queue_scb(ahd, scb);
	}
}

/*
 * SCSI controller interrupt handler.
 */
void
ahd_linux_isr(int irq, void *dev_id, struct pt_regs * regs)
{
	struct	ahd_softc *ahd;
	struct	ahd_cmd *acmd;
	u_long	flags;
	struct	ahd_linux_device *next_dev;

	ahd = (struct ahd_softc *) dev_id;
	ahd_lock(ahd, &flags); 
	ahd_intr(ahd);
	acmd = TAILQ_FIRST(&ahd->platform_data->completeq);
	TAILQ_INIT(&ahd->platform_data->completeq);
	next_dev = ahd_linux_next_device_to_run(ahd);
	ahd_unlock(ahd, &flags);
	if (next_dev) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		tasklet_schedule(&ahd->platform_data->runq_tasklet);
#else
		ahd_runq_tasklet((unsigned long)ahd);
#endif
	}
	if (acmd != NULL)
		ahd_linux_run_complete_queue(ahd, acmd);
}

void
ahd_platform_flushwork(struct ahd_softc *ahd)
{
	struct ahd_cmd *acmd;

	acmd = TAILQ_FIRST(&ahd->platform_data->completeq);
	TAILQ_INIT(&ahd->platform_data->completeq);
	if (acmd != NULL)
		ahd_linux_run_complete_queue(ahd, acmd);
}

static struct ahd_linux_target*
ahd_linux_alloc_target(struct ahd_softc *ahd, u_int channel, u_int target)
{
	struct ahd_linux_target *targ;
	u_int target_offset;

	targ = malloc(sizeof(*targ), M_DEVBUG, M_NOWAIT);
	if (targ == NULL)
		return (NULL);
	memset(targ, 0, sizeof(*targ));
	targ->channel = channel;
	targ->target = target;
	targ->ahd = ahd;
	target_offset = target;
	if (channel != 0)
		target_offset += 8;
	ahd->platform_data->targets[target_offset] = targ;
	return (targ);
}

static void
ahd_linux_free_target(struct ahd_softc *ahd, struct ahd_linux_target *targ)
{
	u_int target_offset;

	target_offset = targ->target;
	if (targ->channel != 0)
		target_offset += 8;
	ahd->platform_data->targets[target_offset] = NULL;
	free(targ, M_DEVBUF);
}

static struct ahd_linux_device*
ahd_linux_alloc_device(struct ahd_softc *ahd,
		 struct ahd_linux_target *targ, u_int lun)
{
	struct ahd_linux_device *dev;

	dev = malloc(sizeof(*dev), M_DEVBUG, M_NOWAIT);
	if (dev == NULL)
		return (NULL);
	memset(dev, 0, sizeof(*dev));
	init_timer(&dev->timer);
	TAILQ_INIT(&dev->busyq);
	dev->flags = AHD_DEV_UNCONFIGURED;
	dev->lun = lun;
	dev->target = targ;

	/*
	 * We start out life using untagged
	 * transactions of which we allow one.
	 */
	dev->openings = 1;

	/*
	 * Set maxtags to 0.  This will be changed if we
	 * later determine that we are dealing with
	 * a tagged queuing capable device.
	 */
	dev->maxtags = 0;
	
	targ->refcount++;
	targ->devices[lun] = dev;
	return (dev);
}

static void
ahd_linux_free_device(struct ahd_softc *ahd, struct ahd_linux_device *dev)
{
	struct ahd_linux_target *targ;

	del_timer(&dev->timer);
	targ = dev->target;
	targ->devices[dev->lun] = NULL;
	free(dev, M_DEVBUF);
	targ->refcount--;
	if (targ->refcount == 0)
		ahd_linux_free_target(ahd, targ);
}

/*
 * Return a string describing the driver.
 */
const char *
ahd_linux_info(struct Scsi_Host *host)
{
	static char buffer[512];
	char	ahd_info[256];
	char   *bp;
	struct ahd_softc *ahd;

	bp = &buffer[0];
	ahd = *(struct ahd_softc **)host->hostdata;
	memset(bp, 0, sizeof(buffer));
	strcpy(bp, "Adaptec AIC79XX PCI-X SCSI HBA DRIVER, Rev ");
	strcat(bp, AIC79XX_DRIVER_VERSION);
	strcat(bp, "\n");
	strcat(bp, "        <");
	strcat(bp, ahd->description);
	strcat(bp, ">\n");
	strcat(bp, "        ");
	ahd_controller_info(ahd, ahd_info);
	strcat(bp, ahd_info);
	strcat(bp, "\n");

	return (bp);
}

void
ahd_send_async(struct ahd_softc *ahd, char channel,
	       u_int target, u_int lun, ac_code code, void *arg)
{
	switch (code) {
	case AC_TRANSFER_NEG:
	{
		char	buf[80];
		struct	ahd_linux_target *targ;
		struct	info_str info;
		struct	ahd_initiator_tinfo *tinfo;
		struct	ahd_tmode_tstate *tstate;

		info.buffer = buf;
		info.length = sizeof(buf);
		info.offset = 0;
		info.pos = 0;
		tinfo = ahd_fetch_transinfo(ahd, channel, ahd->our_id,
					    target, &tstate);

		/*
		 * Don't bother reporting results while
		 * negotiations are still pending.
		 */
		if (tinfo->curr.period != tinfo->goal.period
		 || tinfo->curr.width != tinfo->goal.width
		 || tinfo->curr.offset != tinfo->goal.offset
		 || tinfo->curr.ppr_options != tinfo->goal.ppr_options)
			if (bootverbose == 0)
				break;

		/*
		 * Don't bother reporting results that
		 * are identical to those last reported.
		 */
		targ = ahd->platform_data->targets[target];
		if (targ == NULL)
			break;
		if (tinfo->curr.period == targ->last_tinfo.period
		 && tinfo->curr.width == targ->last_tinfo.width
		 && tinfo->curr.offset == targ->last_tinfo.offset
		 && tinfo->curr.ppr_options == targ->last_tinfo.ppr_options)
			if (bootverbose == 0)
				break;

		targ->last_tinfo.period = tinfo->curr.period;
		targ->last_tinfo.width = tinfo->curr.width;
		targ->last_tinfo.offset = tinfo->curr.offset;
		targ->last_tinfo.ppr_options = tinfo->curr.ppr_options;

		printf("(%s:%c:", ahd_name(ahd), channel);
		if (target == CAM_TARGET_WILDCARD)
			printf("*): ");
		else
			printf("%d): ", target);
		ahd_format_transinfo(&info, &tinfo->curr);
		if (info.pos < info.length)
			*info.buffer = '\0';
		else
			buf[info.length - 1] = '\0';
		printf("%s", buf);
		break;
	}
        case AC_SENT_BDR:
		break;
        case AC_BUS_RESET:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
		if (ahd->platform_data->host != NULL) {
			scsi_report_bus_reset(ahd->platform_data->host,
					      channel - 'A');
		}
#endif
                break;
        default:
                panic("ahd_send_async: Unexpected async event");
        }
}

/*
 * Calls the higher level scsi done function and frees the scb.
 */
void
ahd_done(struct ahd_softc *ahd, struct scb * scb)
{
	Scsi_Cmnd *cmd;
	struct ahd_linux_device *dev;

	LIST_REMOVE(scb, pending_links);
	if ((scb->flags & SCB_UNTAGGEDQ) != 0) {
		struct scb_tailq *untagged_q;
		int target_offset;

		target_offset = SCB_GET_TARGET_OFFSET(ahd, scb);
		untagged_q = &(ahd->untagged_queues[target_offset]);
		TAILQ_REMOVE(untagged_q, scb, links.tqe);
		ahd_run_untagged_queue(ahd, untagged_q);
	}

	if ((scb->flags & SCB_ACTIVE) == 0) {
		printf("SCB %d done'd twice\n", scb->hscb->tag);
		ahd_dump_card_state(ahd);
		panic("Stopping for safety");
	}
	cmd = scb->io_ctx;
	dev = scb->platform_data->dev;
	dev->active--;
	dev->openings++;
	ahd_linux_unmap_scb(ahd, scb);
	if (scb->flags & SCB_SENSE) {
		memset(cmd->sense_buffer, 0, sizeof(cmd->sense_buffer));
		memcpy(cmd->sense_buffer, ahd_get_sense_buf(ahd, scb),
		       MIN(sizeof(struct scsi_sense_data),
			   sizeof(cmd->sense_buffer)));
		cmd->result |= (DRIVER_SENSE << 24);
	} else if (scb->flags & SCB_PKT_SENSE) {
		struct scsi_status_iu_header *siu;
		u_int sense_len;

		/*
		 * Copy only the sense data into the provided buffer.
		 */
		siu = (struct scsi_status_iu_header *)scb->sense_data;
		sense_len = MIN(scsi_4btoul(siu->sense_length),
				sizeof(cmd->sense_buffer));
		memset(cmd->sense_buffer, 0, sizeof(cmd->sense_buffer));
		memcpy(cmd->sense_buffer,
		       ahd_get_sense_buf(ahd, scb) + SIU_SENSE_OFFSET(siu),
		       sense_len);

#ifdef AHD_DEBUG
		if (ahd_debug & AHD_SHOW_SENSE) {
			int i;

			printf("Copied %d bytes of sense data offset %d:",
			       sense_len, SIU_SENSE_OFFSET(siu));
			for (i = 0; i < sense_len; i++)
				printf(" 0x%x", cmd->sense_buffer[i]);
			printf("\n");
		}
#endif
		cmd->result |= (DRIVER_SENSE << 24);
	} else {
		/*
		 * Guard against stale sense data.
		 * The Linux mid-layer assumes that sense
		 * was retrieved anytime the first byte of
		 * the sense buffer looks "sane".
		 */
		cmd->sense_buffer[0] = 0;
	}
	if (ahd_get_transaction_status(scb) == CAM_REQ_INPROG) {
		uint32_t amount_xferred;

		amount_xferred =
		    ahd_get_transfer_length(scb) - ahd_get_residual(scb);
		if (amount_xferred < scb->io_ctx->underflow) {
			printf("Saw underflow (%ld of %ld bytes). "
			       "Treated as error\n",
				ahd_get_residual(scb),
				ahd_get_transfer_length(scb));
			ahd_set_transaction_status(scb, CAM_DATA_RUN_ERR);
		} else {
			ahd_set_transaction_status(scb, CAM_REQ_CMP);
			ahd_linux_sniff_command(ahd, cmd, scb);
		}
	} else if (ahd_get_transaction_status(scb) == DID_OK) {
		ahd_linux_handle_scsi_status(ahd, dev, scb);
	} else if (ahd_get_transaction_status(scb) == DID_NO_CONNECT) {
		/*
		 * Should a selection timeout kill the device?
		 * That depends on whether the selection timeout
		 * is persistent.  Since we have no guarantee that
		 * the mid-layer will issue an inquiry for this device
		 * again, we can't just kill it off.
		dev->flags |= AHD_DEV_UNCONFIGURED;
		 */
	}

	if (dev->openings == 1
	 && ahd_get_transaction_status(scb) == CAM_REQ_CMP
	 && ahd_get_scsi_status(scb) != SCSI_STATUS_QUEUE_FULL)
		dev->tag_success_count++;
	/*
	 * Some devices deal with temporary internal resource
	 * shortages by returning queue full.  When the queue
	 * full occurrs, we throttle back.  Slowly try to get
	 * back to our previous queue depth.
	 */
	if ((dev->openings + dev->active) < dev->maxtags
	 && dev->tag_success_count > AHD_TAG_SUCCESS_INTERVAL) {
		dev->tag_success_count = 0;
		dev->openings++;
	}

	if (dev->active == 0)
		dev->commands_since_idle_or_otag = 0;

	if (TAILQ_EMPTY(&dev->busyq)) {
		if ((dev->flags & AHD_DEV_UNCONFIGURED) != 0
		 && dev->active == 0)
			ahd_linux_free_device(ahd, dev);
	} else if ((dev->flags & AHD_DEV_ON_RUN_LIST) == 0) {
		TAILQ_INSERT_TAIL(&ahd->platform_data->device_runq, dev, links);
		dev->flags |= AHD_DEV_ON_RUN_LIST;
	}

	if ((scb->flags & SCB_RECOVERY_SCB) != 0) {
		printf("Recovery SCB completes\n");
		up(&ahd->platform_data->eh_sem);
	}

	ahd_free_scb(ahd, scb);
	ahd_linux_queue_cmd_complete(ahd, cmd);
}

static void
ahd_linux_handle_scsi_status(struct ahd_softc *ahd,
			     struct ahd_linux_device *dev, struct scb *scb)
{
	/*
	 * We don't currently trust the mid-layer to
	 * properly deal with queue full or busy.  So,
	 * when one occurs, we tell the mid-layer to
	 * unconditionally requeue the command to us
	 * so that we can retry it ourselves.  We also
	 * implement our own throttling mechanism so
	 * we don't clobber the device with too many
	 * commands.
	 */
	switch (ahd_get_scsi_status(scb)) {
	default:
		break;
	case SCSI_STATUS_QUEUE_FULL:
	{
		/*
		 * By the time the core driver has returned this
		 * command, all other commands that were queued
		 * to us but not the device have been returned.
		 * This ensures that dev->active is equal to
		 * the number of commands actually queued to
		 * the device.
		 */
		dev->tag_success_count = 0;
		if (dev->active != 0) {
			/*
			 * Drop our opening count to the number
			 * of commands currently outstanding.
			 */
			dev->openings = 0;
#ifdef AHD_DEBUG
			if (ahd_debug & AHD_SHOW_QFULL) {
				ahd_print_path(ahd, scb);
				printf("Dropping tag count to %d\n",
				       dev->active);
			}
#endif
			if (dev->active == dev->tags_on_last_queuefull) {

				dev->last_queuefull_same_count++;
				/*
				 * If we repeatedly see a queue full
				 * at the same queue depth, this
				 * device has a fixed number of tag
				 * slots.  Lock in this tag depth
				 * so we stop seeing queue fulls from
				 * this device.
				 */
				if (dev->last_queuefull_same_count
				 == AHD_LOCK_TAGS_COUNT) {
					dev->maxtags = dev->active;
					ahd_print_path(ahd, scb);
					printf("Locking max tag count at %d\n",
					       dev->active);
				}
			} else {
				dev->tags_on_last_queuefull = dev->active;
				dev->last_queuefull_same_count = 0;
			}
			ahd_set_transaction_status(scb, CAM_REQUEUE_REQ);
			ahd_set_scsi_status(scb, SCSI_STATUS_OK);
			break;
		}
		/*
		 * Drop down to a single opening, and treat this
		 * as if the target return BUSY SCSI status.
		 */
		dev->openings = 1;
		/* FALLTHROUGH */
	}
	case SCSI_STATUS_BUSY:
		/*
		 * Set a short timer to defer sending commands for
		 * a bit since Linux will not delay in this case.
		 */
		if ((dev->flags & AHD_DEV_TIMER_ACTIVE) != 0) {
			printf("%s:%c:%d: Device Timer still active during "
			       "busy processing\n", ahd_name(ahd),
				dev->target->channel, dev->target->target);
			break;
		}
		dev->flags |= AHD_DEV_TIMER_ACTIVE;
		dev->qfrozen++;
		init_timer(&dev->timer);
		dev->timer.data = (u_long)dev;
		dev->timer.expires = jiffies + (HZ/2);
		dev->timer.function = ahd_linux_dev_timed_unfreeze;
		add_timer(&dev->timer);
		break;
	}
}

static void
ahd_linux_filter_command(struct ahd_softc *ahd, Scsi_Cmnd *cmd, struct scb *scb)
{
	switch (cmd->cmnd[0]) {
	case INQUIRY:
	{
		struct	ahd_devinfo devinfo;
		struct	scsi_inquiry *inq;
		struct	scsi_inquiry_data *sid;
		struct	ahd_initiator_tinfo *tinfo;
		struct	ahd_transinfo *user;
		struct	ahd_transinfo *goal;
		struct	ahd_transinfo *curr;
		struct	ahd_tmode_tstate *tstate;
		struct	ahd_linux_device *dev;
		u_int	scsiid;
		int	transferred_len;
		int	minlen;
		int	was_configured;
		u_int	width;
		u_int	period;
		u_int	offset;
		u_int	ppr_options;
		u_int	trans_version;
		u_int	prot_version;
		static	int warned_user;

		 /*
		  * Validate the command.  We only want to filter
		  * standard inquiry commands, not those querying
		  * Vital Product Data.
		  */
		inq = (struct scsi_inquiry *)cmd->cmnd;
		if ((inq->byte2 & SI_EVPD) != 0
		 || inq->page_code != 0)
			break;

		if (cmd->use_sg != 0) {
			printf("%s: SG Inquiry response ignored\n",
			       ahd_name(ahd));
			break;
		}
		transferred_len = ahd_get_transfer_length(scb)
				- ahd_get_residual(scb);
		sid = (struct scsi_inquiry_data *)cmd->request_buffer;

		/*
		 * Determine if this lun actually exists.  If so,
		 * hold on to its corresponding device structure.
		 * If not, make sure we release the device and
		 * don't bother processing the rest of this inquiry
		 * command.
		 */
		dev = ahd_linux_get_device(ahd, cmd->channel,
					   cmd->target, cmd->lun,
					   /*alloc*/FALSE);
		was_configured = dev->flags & AHD_DEV_UNCONFIGURED;
		if (transferred_len >= 1
		 && SID_QUAL(sid) == SID_QUAL_LU_CONNECTED) {

			dev->flags &= ~AHD_DEV_UNCONFIGURED;
		} else {
			dev->flags |= AHD_DEV_UNCONFIGURED;
			break;
		}

		/*
		 * Update our notion of this device's transfer
		 * negotiation capabilities.
		 */
		scsiid = BUILD_SCSIID(ahd, cmd);
		ahd_compile_devinfo(&devinfo, SCSIID_OUR_ID(scsiid),
				    cmd->target, cmd->lun,
				    SCSIID_CHANNEL(ahd, scsiid),
				    ROLE_INITIATOR);
		tinfo = ahd_fetch_transinfo(ahd, devinfo.channel,
					    devinfo.our_scsiid,
					    devinfo.target, &tstate);
		user = &tinfo->user;
		goal = &tinfo->goal;
		curr = &tinfo->curr;
		width = user->width;
		period = user->period;
		offset = user->offset;
		ppr_options = user->ppr_options;
		trans_version = user->transport_version;
		prot_version = user->protocol_version;
		/*
		 * If we have read streaming info for this controller,
		 * apply it to this target.
		 */
		if (warned_user == 0
		 && ahd->unit >= NUM_ELEMENTS(aic79xx_rd_strm_info)) {

			printf("aic79xx: WARNING, insufficient "
			       "rd_strm instances for installed "
			       "controllers. Using defaults\n");
			printf("aic79xx: Please update the "
			       "aic79xx_rd_strm_info array in the "
			       "aic79xx.c source file.\n");
			warned_user++;
		} else {
			uint16_t rd_strm_mask;

			rd_strm_mask = aic79xx_rd_strm_info[ahd->unit];
			if ((rd_strm_mask & devinfo.target_mask) == 0)
				ppr_options &= ~MSG_EXT_PPR_RD_STRM;
		}
		
		minlen = offsetof(struct scsi_inquiry_data, version) + 1;
		if (transferred_len >= minlen) {
			prot_version = SID_ANSI_REV(sid);

			/*
			 * Only attempt SPI3 once we've verified that
			 * the device claims to support SPI3 features.
			 */
			if (prot_version < SCSI_REV_2)
				trans_version = SID_ANSI_REV(sid);
			else
				trans_version = SCSI_REV_2;
		}

		minlen = offsetof(struct scsi_inquiry_data, flags) + 1;
		if (transferred_len >= minlen
		 && (sid->additional_length + 4) >= minlen) {
			if ((sid->flags & SID_WBus16) == 0)
				width = MSG_EXT_WDTR_BUS_8_BIT;
			if ((sid->flags & SID_Sync) == 0) {
				period = 0;
				offset = 0;
				ppr_options = 0;
			}
		} else {
			/* Keep current settings */
			break;
		}
		minlen = offsetof(struct scsi_inquiry_data, spi3data) + 1;
		/*
		 * This is a kludge to deal with inquiry requests that
		 * are not large enough for us to pull the spi3/4 bits.
		 * In this case, we assume that a device that tells us
		 * they can provide inquiry data that spans the SPI3
		 * bits and says its SCSI3 can handle a PPR request.
		 * If the inquiry request has sufficient buffer space to
		 * cover SPI3 bits, we honor them regardless of reported
		 * SCSI REV.  We also allow any device that has had its
		 * goal ppr_options set to allow DT speeds to keep that
		 * option if a short inquiry occurs that would fail the
		 * normal tests outlined above.
		 */
		if ((sid->additional_length + 4) >= minlen) {
			if (transferred_len >= minlen) {
				 if ((sid->spi3data & SID_SPI_CLOCK_DT) == 0)
					ppr_options = 0;
				 if ((sid->spi3data & SID_SPI_IUS) == 0)
					ppr_options &= (MSG_EXT_PPR_DT_REQ
						      | MSG_EXT_PPR_QAS_REQ);
			} else if (was_configured
				&& (curr->transport_version
				 == user->transport_version)) {

				/* Keep already existant settings. */
				break;
			} else if ((goal->ppr_options & MSG_EXT_PPR_DT_REQ)== 0)
				ppr_options = 0;

			if (curr->protocol_version > SCSI_REV_2)
				trans_version = user->transport_version;
		} else {
			ppr_options = 0;
		}
		ahd_validate_width(ahd, /*tinfo limit*/NULL, &width,
				   ROLE_UNKNOWN);

		ahd_find_syncrate(ahd, &period, &ppr_options, AHD_SYNCRATE_MAX);
		ahd_validate_offset(ahd, /*tinfo limit*/NULL, period,
				    &offset, width, ROLE_UNKNOWN);
		if (offset == 0 || period == 0) {
			period = 0;
			offset = 0;
			ppr_options = 0;
		}
		/* Apply our filtered user settings. */
		curr->transport_version = trans_version;
		curr->protocol_version = prot_version;
		ahd_set_width(ahd, &devinfo, width,
			      AHD_TRANS_GOAL, /*paused*/FALSE);
		ahd_set_syncrate(ahd, &devinfo, period, offset, ppr_options,
				 AHD_TRANS_GOAL, /*paused*/FALSE);
		break;
	}
	default:
		panic("ahd_linux_filter_command: Unexpected Command type  %x\n",
		      cmd->cmnd[0]);
		break;
	}
}

void
ahd_freeze_simq(struct ahd_softc *ahd)
{
	ahd->platform_data->qfrozen++;
	if (ahd->platform_data->qfrozen == 1)
		scsi_block_requests(ahd->platform_data->host);
}

void
ahd_release_simq(struct ahd_softc *ahd)
{
	u_long s;
	int    unblock_reqs;

	unblock_reqs = 0;
	ahd_lock(ahd, &s);
	if (ahd->platform_data->qfrozen > 0)
		ahd->platform_data->qfrozen--;
	if (ahd->platform_data->qfrozen == 0) {
		unblock_reqs = 1;
	}
	ahd_unlock(ahd, &s);
	/*
	 * There is still a race here.  The mid-layer
	 * should keep its own freeze count and use
	 * a bottom half handler to run the queues
	 * so we can unblock with our own lock held.
	 */
	if (unblock_reqs) {
		scsi_unblock_requests(ahd->platform_data->host);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		tasklet_schedule(&ahd->platform_data->runq_tasklet);
#else
		ahd_runq_tasklet((unsigned long)ahd);
#endif
	}
}

#if NOT_YET
static void
ahd_linux_sem_timeout(u_long arg)
{
	struct semaphore *sem;

	sem = (struct semaphore *)arg;
	up(sem);
}

static int
ahd_linux_queue_recovery_cmd(Scsi_Cmnd *cmd, scb_flag flag)
{
	struct ahd_softc *ahd;
	struct ahd_cmd *acmd;
	struct ahd_cmd *list_acmd;
	struct ahd_linux_device *dev;
	struct scb *pending_scb;
	u_long s;
	u_int  saved_scbptr;
	u_int  active_scb_index;
	u_int  last_phase;
	int    retval;
	int    paused;
	int    wait;
	int    disconnected;

	paused = FALSE;
	wait = FALSE;
	ahd = *(struct ahd_softc **)cmd->host->hostdata;
	acmd = (struct ahd_cmd *)cmd;

	printf("%s:%d:%d:%d: Attempting to queue a%s message\n",
	       ahd_name(ahd), cmd->channel, cmd->target, cmd->lun,
	       flag == SCB_ABORT ? "n ABORT" : " TARGET RESET");

	/*
	 * It is a bug that the upper layer takes
	 * this lock just prior to calling us.
	 */
	spin_unlock_irq(&io_request_lock);

	ahd_lock(ahd, &s);

	/*
	 * First determine if we currently own this command.
	 * Start by searching the device queue.  If not found
	 * there, check the pending_scb list.  If not found
	 * at all, and the system wanted us to just abort the
	 * command return success.
	 */
	dev = ahd_linux_get_device(ahd, cmd->channel, cmd->target,
				   cmd->lun, /*alloc*/FALSE);

	if (dev == NULL) {
		/*
		 * No target device for this command exists,
		 * so we must not still own the command.
		 */
		printf("%s:%d:%d:%d: Is not an active device\n",
		       ahd_name(ahd), cmd->channel, cmd->target, cmd->lun);
		retval = SUCCESS;
		goto no_cmd;
	}

	TAILQ_FOREACH(list_acmd, &dev->busyq, acmd_links.tqe) {
		if (list_acmd == acmd)
			break;
	}

	if (list_acmd != NULL) {
		printf("%s:%d:%d:%d: Command found on device queue\n",
		       ahd_name(ahd), cmd->channel, cmd->target, cmd->lun);
		if (flag == SCB_ABORT) {
			TAILQ_REMOVE(&dev->busyq, list_acmd, acmd_links.tqe);
			cmd->result = DID_ABORT << 16;
			ahd_linux_queue_cmd_complete(ahd, cmd);
			retval = SUCCESS;
			goto done;
		}
	}

	/*
	 * See if we can find a matching cmd in the pending list.
	 */
	LIST_FOREACH(pending_scb, &ahd->pending_scbs, pending_links) {
		if (pending_scb->io_ctx == cmd)
			break;
	}

	if (pending_scb == NULL && flag == SCB_DEVICE_RESET) {

		/* Any SCB for this device will do for a target reset */
		LIST_FOREACH(pending_scb, &ahd->pending_scbs, pending_links) {
		  	if (ahd_match_scb(ahd, pending_scb, cmd->target,
					  cmd->channel, CAM_LUN_WILDCARD,
					  SCB_LIST_NULL, ROLE_INITIATOR) == 0)
				break;
		}
	}

	if (pending_scb == NULL) {
		printf("%s:%d:%d:%d: Command not found\n",
		       ahd_name(ahd), cmd->channel, cmd->target, cmd->lun);
		goto no_cmd;
	}

	if ((pending_scb->flags & SCB_RECOVERY_SCB) != 0) {
		/*
		 * We can't queue two recovery actions using the same SCB
		 */
		retval = FAILED;
		goto  done;
	}

	/*
	 * Ensure that the card doesn't do anything
	 * behind our back.  Also make sure that we
	 * didn't "just" miss an interrupt that would
	 * affect this cmd.
	 */
	ahd->flags |= AHD_ALL_INTERRUPTS;
	do {
		ahd_intr(ahd);
		ahd_pause(ahd);
		ahd_clear_critical_section(ahd);
	} while (ahd_inb(ahd, INTSTAT) & INT_PEND);
	ahd->flags &= ~AHD_ALL_INTERRUPTS;
	paused = TRUE;

	ahd_dump_card_state(ahd);

	if ((pending_scb->flags & SCB_ACTIVE) == 0) {
		printf("%s:%d:%d:%d: Command already completed\n",
		       ahd_name(ahd), cmd->channel, cmd->target, cmd->lun);
		goto no_cmd;
	}

	disconnected = TRUE;
	if (flag == SCB_ABORT) {
		if (ahd_search_qinfifo(ahd, cmd->target, cmd->channel + 'A',
				       cmd->lun, pending_scb->hscb->tag,
				       ROLE_INITIATOR, CAM_REQ_ABORTED,
				       SEARCH_COMPLETE) > 0) {
			printf("%s:%d:%d:%d: Cmd aborted from QINFIFO\n",
			       ahd_name(ahd), cmd->channel, cmd->target,
					cmd->lun);
			retval = SUCCESS;
			goto done;
		}
	} else if (ahd_search_qinfifo(ahd, cmd->target, cmd->channel + 'A',
				      cmd->lun, pending_scb->hscb->tag,
				      ROLE_INITIATOR, /*status*/0,
				      SEARCH_COUNT) > 0) {
		disconnected = FALSE;
	}

	/*
	 * At this point, pending_scb is the scb associated with the
	 * passed in command.  That command is currently active on the
	 * bus, is in the disconnected state, or we're hoping to find
	 * a command for the same target active on the bus to abuse to
	 * send a BDR.  Queue the appropriate message based on which of
	 * these states we are in.
	 */
	last_phase = ahd_inb(ahd, LASTPHASE);
	saved_scbptr = ahd_inb(ahd, SCBPTR);
	active_scb_index = ahd_inb(ahd, SCB_TAG);
	if (last_phase != P_BUSFREE
	 && (pending_scb->hscb->tag == active_scb_index
	  || (flag == SCB_DEVICE_RESET
	   && SCSIID_TARGET(ahd, ahd_inb(ahd, SAVED_SCSIID)) == cmd->target))) {

		/*
		 * We're active on the bus, so assert ATN
		 * and hope that the target responds.
		 */
		pending_scb = ahd_lookup_scb(ahd, active_scb_index);
		pending_scb->flags |= SCB_RECOVERY_SCB|flag;
		ahd_outb(ahd, MSG_OUT, HOST_MSG);
		ahd_outb(ahd, SCSISIGO, last_phase|ATNO);
		printf("%s:%d:%d:%d: Device is active, asserting ATN\n",
		       ahd_name(ahd), cmd->channel, cmd->target, cmd->lun);
		wait = TRUE;
	} else if (disconnected) {

		/*
		 * Actually re-queue this SCB in an attempt
		 * to select the device before it reconnects.
		 * In either case (selection or reselection),
		 * we will now issue the approprate message
		 * to the timed-out device.
		 *
		 * Set the MK_MESSAGE control bit indicating
		 * that we desire to send a message.  We
		 * also set the disconnected flag since
		 * in the paging case there is no guarantee
		 * that our SCB control byte matches the
		 * version on the card.  We don't want the
		 * sequencer to abort the command thinking
		 * an unsolicited reselection occurred.
		 */
		pending_scb->hscb->control |= MK_MESSAGE|DISCONNECTED;
		pending_scb->flags |= SCB_RECOVERY_SCB|flag;

		/*
		 * In the non-paging case, the sequencer will
		 * never re-reference the in-core SCB.
		 * To make sure we are notified during
		 * reslection, set the MK_MESSAGE flag in
		 * the card's copy of the SCB.
		 */
		ahd_outb(ahd, SCBPTR, pending_scb->hscb->tag);
		ahd_outb(ahd, SCB_CONTROL,
			 ahd_inb(ahd, SCB_CONTROL)|MK_MESSAGE);

		/*
		 * Clear out any entries in the QINFIFO first
		 * so we are the next SCB for this target
		 * to run.
		 */
		ahd_search_qinfifo(ahd, cmd->target, cmd->channel + 'A',
				   cmd->lun, SCB_LIST_NULL, ROLE_INITIATOR,
				   CAM_REQUEUE_REQ, SEARCH_COMPLETE);
		ahd_print_path(ahd, pending_scb);
		printf("Queuing a recovery SCB\n");
		ahd_qinfifo_requeue_tail(ahd, pending_scb);
		ahd_outb(ahd, SCBPTR, saved_scbptr);
		printf("%s:%d:%d:%d: Device is disconnected, re-queuing SCB\n",
		       ahd_name(ahd), cmd->channel, cmd->target, cmd->lun);
		wait = TRUE;
	} else {
		printf("%s:%d:%d:%d: Unable to deliver message\n",
		       ahd_name(ahd), cmd->channel, cmd->target, cmd->lun);
		retval = FAILED;
		goto done;
	}

no_cmd:
	/*
	 * Our assumption is that if we don't have the command, no
	 * recovery action was required, so we return success.  Again,
	 * the semantics of the mid-layer recovery engine are not
	 * well defined, so this may change in time.
	 */
	retval = SUCCESS;
done:
	if (paused)
		ahd_unpause(ahd);
	if (wait) {
		struct timer_list timer;
		int ret;

		ahd_unlock(ahd, &s);
		init_timer(&timer);
		timer.data = (u_long)&ahd->platform_data->eh_sem;
		timer.expires = jiffies + (5 * HZ);
		timer.function = ahd_linux_sem_timeout;
		add_timer(&timer);
		printf("Recovery code sleeping\n");
		down(&ahd->platform_data->eh_sem);
		printf("Recovery code awake\n");
        	ret = del_timer(&timer);
		if (ret == 0) {
			printf("Timer Expired\n");
			retval = FAILED;
		}
		ahd_lock(ahd, &s);
	}
	acmd = TAILQ_FIRST(&ahd->platform_data->completeq);
	TAILQ_INIT(&ahd->platform_data->completeq);
	ahd_unlock(ahd, &s);
	if (acmd != NULL)
		ahd_linux_run_complete_queue(ahd, acmd);
	ahd_runq_tasklet((unsigned long)ahd);
	spin_lock_irq(&io_request_lock);
	return (retval);
}
#endif

static void
ahd_linux_dev_timed_unfreeze(u_long arg)
{
	struct ahd_linux_device *dev;
	struct ahd_softc *ahd;
	u_long s;

	dev = (struct ahd_linux_device *)arg;
	ahd = dev->target->ahd;
	ahd_lock(ahd, &s);
	dev->flags &= ~AHD_DEV_TIMER_ACTIVE;
	if (dev->qfrozen > 0)
		dev->qfrozen--;
	if (dev->qfrozen == 0
	 && (dev->flags & AHD_DEV_ON_RUN_LIST) == 0)
		ahd_linux_run_device_queue(ahd, dev);
	ahd_unlock(ahd, &s);
}

/*
 * Abort the current SCSI command(s).
 */
int
ahd_linux_abort(Scsi_Cmnd *cmd)
{
	struct ahd_softc *ahd;
	u_long s;
#if NOTYET
	struct ahd_cmd *acmd;
	int    found;
#endif

	ahd = *(struct ahd_softc **)cmd->host->hostdata;
#if NOTYET
	int error;

	error = ahd_linux_queue_recovery_cmd(cmd, SCB_ABORT);
	if (error != 0)
		printf("aic79xx_abort returns 0x%x\n", error);
	return (error);
#else
	printf("Abort called for cmd %p\n", cmd);
	ahd_lock(ahd, &s);
	ahd_dump_card_state(ahd);
	ahd_unlock(ahd, &s);
	return (FAILED);
#endif
}

/*
 * Attempt to send a target reset message to the device that timed out.
 */
int
ahd_linux_dev_reset(Scsi_Cmnd *cmd)
{
	struct ahd_softc *ahd;
#if NOTYET
	struct ahd_cmd *acmd;
	u_long s;
	int    found;
#endif

	printf("dev reset called for cmd %p\n", cmd);
	ahd = *(struct ahd_softc **)cmd->host->hostdata;
#if NOTYET
	int error;

	error = ahd_linux_queue_recovery_cmd(cmd, SCB_DEVICE_RESET);
	if (error != 0)
		printf("aic79xx_dev_reset returns 0x%x\n", error);
	return (error);
#else
	return (FAILED);
#endif
}

/*
 * Reset the SCSI bus.
 */
int
ahd_linux_bus_reset(Scsi_Cmnd *cmd)
{
	struct ahd_softc *ahd;
	struct ahd_cmd *acmd;
	u_long s;
	int    found;

	printf("bus reset called for cmd %p\n", cmd);
	/*
	 * It is a bug that the upper layer takes
	 * this lock just prior to calling us.
	 */
	spin_unlock_irq(&io_request_lock);

	ahd = *(struct ahd_softc **)cmd->host->hostdata;
	ahd_lock(ahd, &s);
	found = ahd_reset_channel(ahd, cmd->channel + 'A',
				  /*initiate reset*/TRUE);
	acmd = TAILQ_FIRST(&ahd->platform_data->completeq);
	TAILQ_INIT(&ahd->platform_data->completeq);
	ahd_unlock(ahd, &s);
	if (bootverbose)
		printf("%s: SCSI bus reset delivered. "
		       "%d SCBs aborted.\n", ahd_name(ahd), found);

	if (acmd != NULL)
		ahd_linux_run_complete_queue(ahd, acmd);

	spin_lock_irq(&io_request_lock);
	return (SUCCESS);
}

/*
 * Return the disk geometry for the given SCSI device.
 */
int
ahd_linux_biosparam(Disk *disk, kdev_t dev, int geom[])
{
	int	heads;
	int	sectors;
	int	cylinders;
	int	ret;
	int	extended;
	struct	ahd_softc *ahd;
	struct	buffer_head *bh;

	ahd = *((struct ahd_softc **)disk->device->host->hostdata);
	bh = bread(MKDEV(MAJOR(dev), MINOR(dev) & ~0xf), 0, 1024);

	if (bh) {
		ret = scsi_partsize(bh, disk->capacity,
				    &geom[2], &geom[0], &geom[1]);
		brelse(bh);
		if (ret != -1)
			return (ret);
	}
	heads = 64;
	sectors = 32;
	cylinders = disk->capacity / (heads * sectors);

	if (aic79xx_extended != 0)
		extended = 1;
	else
		extended = (ahd->flags & AHD_EXTENDED_TRANS_A) != 0;
	if (extended && cylinders >= 1024) {
		heads = 255;
		sectors = 63;
		cylinders = disk->capacity / (heads * sectors);
	}
	geom[0] = heads;
	geom[1] = sectors;
	geom[2] = cylinders;
	return (0);
}

/*
 * Free the passed in Scsi_Host memory structures prior to unloading the
 * module.
 */
int
ahd_linux_release(struct Scsi_Host * host)
{
	struct ahd_softc *ahd;
	u_long l;

	ahd_list_lock(&l);
	if (host != NULL) {

		/*
		 * We should be able to just perform
		 * the free directly, but check our
		 * list for extra sanity.
		 */
		ahd = ahd_find_softc(*(struct ahd_softc **)host->hostdata);
		if (ahd != NULL) {
			u_long s;

			ahd_lock(ahd, &s);
			ahd_intr_enable(ahd, FALSE);
			ahd_unlock(ahd, &s);
			ahd_free(ahd);
		}
	}
	ahd_list_unlock(&l);
	return (0);
}

void
ahd_platform_dump_card_state(struct ahd_softc *ahd)
{
	struct ahd_linux_device *dev;
	int target;
	int maxtarget;
	int lun;
	int i;

	maxtarget = (ahd->features & AHD_WIDE) ? 15 : 7;
	for (target = 0; target <=maxtarget; target++) {

		for (lun = 0; lun < AHD_NUM_LUNS; lun++) {
			struct ahd_cmd *acmd;

			dev = ahd_linux_get_device(ahd, 0, target,
						   lun, /*alloc*/FALSE);
			if (dev == NULL)
				continue;

			printf("DevQ(%d:%d:%d): ", 0, target, lun);
			i = 0;
			TAILQ_FOREACH(acmd, &dev->busyq, acmd_links.tqe) {
				if (i++ > AHD_SCB_MAX)
					break;
			}
			printf("%d waiting\n", i);
		}
	}
}

#if defined(MODULE) || LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
static Scsi_Host_Template driver_template = AIC79XX;
Scsi_Host_Template *aic79xx_driver_template = &driver_template;
#include "../scsi_module.c"
#endif
