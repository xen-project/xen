/*
 * Adaptec AIC7xxx device driver for Linux.
 *
 * $Id: //depot/aic7xxx/linux/drivers/scsi/aic7xxx/aic7xxx_osm.c#103 $
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
 * Sources include the Adaptec 1740 driver (aha1740.c), the Ultrastor 24F
 * driver (ultrastor.c), various Linux kernel source, the Adaptec EISA
 * config file (!adp7771.cfg), the Adaptec AHA-2740A Series User's Guide,
 * the Linux Kernel Hacker's Guide, Writing a SCSI Device Driver for Linux,
 * the Adaptec 1542 driver (aha1542.c), the Adaptec EISA overlay file
 * (adp7770.ovl), the Adaptec AHA-2740 Series Technical Reference Manual,
 * the Adaptec AIC-7770 Data Book, the ANSI SCSI specification, the
 * ANSI SCSI-2 specification (draft 10c), ...
 *
 * --------------------------------------------------------------------------
 *
 *  Modifications by Daniel M. Eischen (deischen@iworks.InterWorks.org):
 *
 *  Substantially modified to include support for wide and twin bus
 *  adapters, DMAing of SCBs, tagged queueing, IRQ sharing, bug fixes,
 *  SCB paging, and other rework of the code.
 *
 * --------------------------------------------------------------------------
 * Copyright (c) 1994-2000 Justin T. Gibbs.
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
 *---------------------------------------------------------------------------
 *
 *  Thanks also go to (in alphabetical order) the following:
 *
 *    Rory Bolt     - Sequencer bug fixes
 *    Jay Estabrook - Initial DEC Alpha support
 *    Doug Ledford  - Much needed abort/reset bug fixes
 *    Kai Makisara  - DMAing of SCBs
 *
 *  A Boot time option was also added for not resetting the scsi bus.
 *
 *    Form:  aic7xxx=extended
 *           aic7xxx=no_reset
 *           aic7xxx=verbose
 *
 *  Daniel M. Eischen, deischen@iworks.InterWorks.org, 1/23/97
 *
 *  Id: aic7xxx.c,v 4.1 1997/06/12 08:23:42 deang Exp
 */

/*
 * Further driver modifications made by Doug Ledford <dledford@redhat.com>
 *
 * Copyright (c) 1997-1999 Doug Ledford
 *
 * These changes are released under the same licensing terms as the FreeBSD
 * driver written by Justin Gibbs.  Please see his Copyright notice above
 * for the exact terms and conditions covering my changes as well as the
 * warranty statement.
 *
 * Modifications made to the aic7xxx.c,v 4.1 driver from Dan Eischen include
 * but are not limited to:
 *
 *  1: Import of the latest FreeBSD sequencer code for this driver
 *  2: Modification of kernel code to accomodate different sequencer semantics
 *  3: Extensive changes throughout kernel portion of driver to improve
 *     abort/reset processing and error hanndling
 *  4: Other work contributed by various people on the Internet
 *  5: Changes to printk information and verbosity selection code
 *  6: General reliability related changes, especially in IRQ management
 *  7: Modifications to the default probe/attach order for supported cards
 *  8: SMP friendliness has been improved
 *
 */

/*
 * This is the only file where module.h should
 * embed module global version info.
 */
//#define AHC_MODVERSION_FILE

#include <xen/lib.h>
#include <xen/string.h>
#include "aic7xxx_osm.h"
#include "aic7xxx_inline.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
#include <xen/init.h>		/* __setup */
#endif

#include "../sd.h"		/* For geometry detection */

#include <xen/mm.h>		/* For fetching system memory size */
#include <xen/blk.h>		/* For block_size() */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,0)
/*
 * Lock protecting manipulation of the ahc softc list.
 */
spinlock_t ahc_list_spinlock;
#endif

/*
 * To generate the correct addresses for the controller to issue
 * on the bus.  Originally added for DEC Alpha support.
 */
#define VIRT_TO_BUS(a) (uint32_t)virt_to_bus((void *)(a))

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,3,0)
struct proc_dir_entry proc_scsi_aic7xxx = {
	PROC_SCSI_AIC7XXX, 7, "aic7xxx",
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
#ifdef CONFIG_AIC7XXX_RESET_DELAY_MS
#define AIC7XXX_RESET_DELAY CONFIG_AIC7XXX_RESET_DELAY_MS
#else
#define AIC7XXX_RESET_DELAY 500
#endif

/*
 * Control collection of SCSI transfer statistics for the /proc filesystem.
 *
 * NOTE: Do NOT enable this when running on kernels version 1.2.x and below.
 * NOTE: This does affect performance since it has to maintain statistics.
 */
#ifdef CONFIG_AIC7XXX_PROC_STATS
#define AIC7XXX_PROC_STATS
#endif

/*
 * To change the default number of tagged transactions allowed per-device,
 * add a line to the lilo.conf file like:
 * append="aic7xxx=verbose,tag_info:{{32,32,32,32},{32,32,32,32}}"
 * which will result in the first four devices on the first two
 * controllers being set to a tagged queue depth of 32.
 *
 * The tag_commands is an array of 16 to allow for wide and twin adapters.
 * Twin adapters will use indexes 0-7 for channel 0, and indexes 8-15
 * for channel 1.
 */
typedef struct {
	uint8_t tag_commands[16];	/* Allow for wide/twin adapters. */
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
 * the devices on the first probed aic7xxx adapter.
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
adapter_tag_info_t aic7xxx_tag_info[] =
{
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	{{4, 64, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 0, 4, 4, 4}},
	{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	{{0, 16, 4, 0, 16, 4, 4, 4, 127, 4, 4, 4, 4, 4, 4, 4}}
};
*/

#ifdef CONFIG_AIC7XXX_CMDS_PER_DEVICE
#define AIC7XXX_CMDS_PER_DEVICE CONFIG_AIC7XXX_CMDS_PER_DEVICE
#else
#define AIC7XXX_CMDS_PER_DEVICE AHC_MAX_QUEUE
#endif

#define AIC7XXX_CONFIGED_TAG_COMMANDS {					\
	AIC7XXX_CMDS_PER_DEVICE, AIC7XXX_CMDS_PER_DEVICE,		\
	AIC7XXX_CMDS_PER_DEVICE, AIC7XXX_CMDS_PER_DEVICE,		\
	AIC7XXX_CMDS_PER_DEVICE, AIC7XXX_CMDS_PER_DEVICE,		\
	AIC7XXX_CMDS_PER_DEVICE, AIC7XXX_CMDS_PER_DEVICE,		\
	AIC7XXX_CMDS_PER_DEVICE, AIC7XXX_CMDS_PER_DEVICE,		\
	AIC7XXX_CMDS_PER_DEVICE, AIC7XXX_CMDS_PER_DEVICE,		\
	AIC7XXX_CMDS_PER_DEVICE, AIC7XXX_CMDS_PER_DEVICE,		\
	AIC7XXX_CMDS_PER_DEVICE, AIC7XXX_CMDS_PER_DEVICE		\
}

/*
 * By default, use the number of commands specified by
 * the users kernel configuration.
 */
static adapter_tag_info_t aic7xxx_tag_info[] =
{
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS},
	{AIC7XXX_CONFIGED_TAG_COMMANDS}
};

/*
 * There should be a specific return value for this in scsi.h, but
 * it seems that most drivers ignore it.
 */
#define DID_UNDERFLOW   DID_ERROR

void
ahc_print_path(struct ahc_softc *ahc, struct scb *scb)
{
	printf("(scsi%d:%c:%d:%d): ",
	       ahc->platform_data->host->host_no,
	       scb != NULL ? SCB_GET_CHANNEL(ahc, scb) : 'X',
	       scb != NULL ? SCB_GET_TARGET(ahc, scb) : -1,
	       scb != NULL ? SCB_GET_LUN(scb) : -1);
}

/*
 * XXX - these options apply unilaterally to _all_ 274x/284x/294x
 *       cards in the system.  This should be fixed.  Exceptions to this
 *       rule are noted in the comments.
 */

/*
 * Skip the scsi bus reset.  Non 0 make us skip the reset at startup.  This
 * has no effect on any later resets that might occur due to things like
 * SCSI bus timeouts.
 */
static uint32_t aic7xxx_no_reset;

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
static int aic7xxx_reverse_scan = 0;

/*
 * Should we force EXTENDED translation on a controller.
 *     0 == Use whatever is in the SEEPROM or default to off
 *     1 == Use whatever is in the SEEPROM or default to on
 */
static uint32_t aic7xxx_extended = 0;

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
static int aic7xxx_pci_parity = 0;

/*
 * Certain newer motherboards have put new PCI based devices into the
 * IO spaces that used to typically be occupied by VLB or EISA cards.
 * This overlap can cause these newer motherboards to lock up when scanned
 * for older EISA and VLB devices.  Setting this option to non-0 will
 * cause the driver to skip scanning for any VLB or EISA controllers and
 * only support the PCI controllers.  NOTE: this means that if the kernel
 * os compiled with PCI support disabled, then setting this to non-0
 * would result in never finding any devices :)
 */
#ifndef CONFIG_AIC7XXX_PROBE_EISA_VL
#define CONFIG_AIC7XXX_PROBE_EISA_VL n
#endif
#if CONFIG_AIC7XXX_PROBE_EISA_VL == n
static int aic7xxx_no_probe = 1;
#else
static int aic7xxx_no_probe;
#endif

/*
 * aic7xxx_detect() has been run, so register all device arrivals
 * immediately with the system rather than deferring to the sorted
 * attachment performed by aic7xxx_detect().
 */
int aic7xxx_detect_complete;

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
static int aic7xxx_seltime = 0x00;

/*
 * Certain devices do not perform any aging on commands.  Should the
 * device be saturated by commands in one portion of the disk, it is
 * possible for transactions on far away sectors to never be serviced.
 * To handle these devices, we can periodically send an ordered tag to
 * force all outstanding transactions to be serviced prior to a new
 * transaction.
 */
int aic7xxx_periodic_otag;

/*
 * Module information and settable options.
 */
#ifdef MODULE
static char *aic7xxx = NULL;
/*
 * Just in case someone uses commas to separate items on the insmod
 * command line, we define a dummy buffer here to avoid having insmod
 * write wild stuff into our code segment
 */
static char dummy_buffer[60] = "Please don't trounce on me insmod!!\n";
/*
MODULE_AUTHOR("Maintainer: Justin T. Gibbs <gibbs@scsiguy.com>");
MODULE_DESCRIPTION("Adaptec Aic77XX/78XX SCSI Host Bus Adapter driver");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,10)
MODULE_LICENSE("Dual BSD/GPL");
#endif
MODULE_PARM(aic7xxx, "s");
MODULE_PARM_DESC(aic7xxx, "period delimited, options string.
	verbose			Enable verbose/diagnostic logging
	no_probe		Disable EISA/VLB controller probing
	no_reset		Supress initial bus resets
	extended		Enable extended geometry on all controllers
	periodic_otag		Send an ordered tagged transaction periodically
				to prevent tag starvation.  This may be
				required by some older disk drives/RAID arrays. 
	reverse_scan		Sort PCI devices highest Bus/Slot to lowest
	tag_info:<tag_str>	Set per-target tag depth
	seltime:<int>		Selection Timeout(0/256ms,1/128ms,2/64ms,3/32ms)

	Sample /etc/modules.conf line:
		Enable verbose logging
		Disable EISA/VLB probing
		Set tag depth on Controller 2/Target 2 to 10 tags
		Shorten the selection timeout to 128ms from its default of 256

	options aic7xxx='\"verbose.no_probe.tag_info:{{}.{}.{..10}}.seltime:1\"'
");
*/
#endif

static void ahc_linux_handle_scsi_status(struct ahc_softc *,
					 struct ahc_linux_device *,
					 struct scb *);
static void ahc_linux_filter_command(struct ahc_softc*, Scsi_Cmnd*,
				     struct scb*);
#if 0
static void ahc_linux_sem_timeout(u_long arg);
static void ahc_linux_freeze_sim_queue(struct ahc_softc *ahc);
static void ahc_linux_release_sim_queue(u_long arg);
#endif
static void ahc_linux_dev_timed_unfreeze(u_long arg);
static int  ahc_linux_queue_recovery_cmd(Scsi_Cmnd *cmd, scb_flag flag);
static void ahc_linux_initialize_scsi_bus(struct ahc_softc *ahc);
static void ahc_linux_select_queue_depth(struct Scsi_Host *host,
					 Scsi_Device *scsi_devs);
static u_int ahc_linux_user_tagdepth(struct ahc_softc *ahc,
				     struct ahc_devinfo *devinfo);
static void ahc_linux_device_queue_depth(struct ahc_softc *ahc,
					 Scsi_Device *device);
static struct ahc_linux_target*	ahc_linux_alloc_target(struct ahc_softc*,
						       u_int, u_int);
static void			ahc_linux_free_target(struct ahc_softc*,
						      struct ahc_linux_target*);
static struct ahc_linux_device*	ahc_linux_alloc_device(struct ahc_softc*,
						       struct ahc_linux_target*,
						       u_int);
static void			ahc_linux_free_device(struct ahc_softc*,
						      struct ahc_linux_device*);
static void ahc_linux_run_device_queue(struct ahc_softc*,
				       struct ahc_linux_device*);
static void ahc_linux_setup_tag_info(char *p, char *end);
static int ahc_linux_next_unit(void);
static void ahc_runq_tasklet(unsigned long data);
#if 0
static int ahc_linux_halt(struct notifier_block *nb, u_long event, void *buf);
#endif

static __inline struct ahc_linux_device*
		     ahc_linux_get_device(struct ahc_softc *ahc, u_int channel,
					  u_int target, u_int lun, int alloc);
static __inline void ahc_linux_queue_cmd_complete(struct ahc_softc *ahc,
						  Scsi_Cmnd *cmd);
static __inline void ahc_linux_run_complete_queue(struct ahc_softc *ahc,
						  struct ahc_cmd *acmd);
static __inline void ahc_linux_check_device_queue(struct ahc_softc *ahc,
						  struct ahc_linux_device *dev);
static __inline struct ahc_linux_device *
		     ahc_linux_next_device_to_run(struct ahc_softc *ahc);
static __inline void ahc_linux_run_device_queues(struct ahc_softc *ahc);
static __inline void ahc_linux_sniff_command(struct ahc_softc*, Scsi_Cmnd*,
					     struct scb*);
static __inline void ahc_linux_unmap_scb(struct ahc_softc*, struct scb*);

static __inline int ahc_linux_map_seg(struct ahc_softc *ahc, struct scb *scb,
		 		      struct ahc_dma_seg *sg,
				      bus_addr_t addr, bus_size_t len);

static __inline struct ahc_linux_device*
ahc_linux_get_device(struct ahc_softc *ahc, u_int channel, u_int target,
	       u_int lun, int alloc)
{
	struct ahc_linux_target *targ;
	struct ahc_linux_device *dev;
	u_int target_offset;

	target_offset = target;
	if (channel != 0)
		target_offset += 8;
	targ = ahc->platform_data->targets[target_offset];
	if (targ == NULL) {
		if (alloc != 0) {
			targ = ahc_linux_alloc_target(ahc, channel, target);
			if (targ == NULL)
				return (NULL);
		} else
			return (NULL);
	}
	dev = targ->devices[lun];
	if (dev == NULL && alloc != 0)
		dev = ahc_linux_alloc_device(ahc, targ, lun);
	return (dev);
}

static __inline void
ahc_linux_queue_cmd_complete(struct ahc_softc *ahc, Scsi_Cmnd *cmd)
{
	/*
	 * Typically, the complete queue has very few entries
	 * queued to it before the queue is emptied by
	 * ahc_linux_run_complete_queue, so sorting the entries
	 * by generation number should be inexpensive.
	 * We perform the sort so that commands that complete
	 * with an error are retuned in the order origionally
	 * queued to the controller so that any subsequent retries
	 * are performed in order.  The underlying ahc routines do
	 * not guarantee the order that aborted commands will be
	 * returned to us.
	 */
	struct ahc_completeq *completeq;
	struct ahc_cmd *list_cmd;
	struct ahc_cmd *acmd;

	/*
	 * If we want the request requeued, make sure there
	 * are sufficent retries.  In the old scsi error code,
	 * we used to be able to specify a result code that
	 * bypassed the retry count.  Now we must use this
	 * hack.
	 */
	if (cmd->result == (CAM_REQUEUE_REQ << 16))
		cmd->retries--;
	completeq = &ahc->platform_data->completeq;
	list_cmd = TAILQ_FIRST(completeq);
	acmd = (struct ahc_cmd *)cmd;
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
ahc_linux_run_complete_queue(struct ahc_softc *ahc, struct ahc_cmd *acmd)
{	
	u_long done_flags;

	ahc_done_lock(ahc, &done_flags);
	while (acmd != NULL) {
		Scsi_Cmnd *cmd;

		cmd = &acmd_scsi_cmd(acmd);
		acmd = TAILQ_NEXT(acmd, acmd_links.tqe);
		cmd->host_scribble = NULL;
		cmd->scsi_done(cmd);
	}
	ahc_done_unlock(ahc, &done_flags);
}

static __inline void
ahc_linux_check_device_queue(struct ahc_softc *ahc,
			     struct ahc_linux_device *dev)
{
	if ((dev->flags & AHC_DEV_FREEZE_TIL_EMPTY) != 0
	 && dev->active == 0) {
		dev->flags &= ~AHC_DEV_FREEZE_TIL_EMPTY;
		dev->qfrozen--;
	}

	if (TAILQ_FIRST(&dev->busyq) == NULL
	 || dev->openings == 0 || dev->qfrozen != 0)
		return;

	ahc_linux_run_device_queue(ahc, dev);
}

static __inline struct ahc_linux_device *
ahc_linux_next_device_to_run(struct ahc_softc *ahc)
{
	
	if ((ahc->flags & AHC_RESOURCE_SHORTAGE) != 0
	 || ahc->platform_data->qfrozen != 0)
		return (NULL);
	return (TAILQ_FIRST(&ahc->platform_data->device_runq));
}

static __inline void
ahc_linux_run_device_queues(struct ahc_softc *ahc)
{
	struct ahc_linux_device *dev;

	while ((dev = ahc_linux_next_device_to_run(ahc)) != NULL) {
		TAILQ_REMOVE(&ahc->platform_data->device_runq, dev, links);
		dev->flags &= ~AHC_DEV_ON_RUN_LIST;
		ahc_linux_check_device_queue(ahc, dev);
	}
}

static __inline void
ahc_linux_sniff_command(struct ahc_softc *ahc, Scsi_Cmnd *cmd, struct scb *scb)
{
	/*
	 * Determine whether we care to filter
	 * information out of this command.  If so,
	 * pass it on to ahc_linux_filter_command() for more
	 * heavy weight processing.
	 */
	if (cmd->cmnd[0] == INQUIRY)
		ahc_linux_filter_command(ahc, cmd, scb);
}

static __inline void
ahc_linux_unmap_scb(struct ahc_softc *ahc, struct scb *scb)
{
	Scsi_Cmnd *cmd;

	cmd = scb->io_ctx;
	ahc_sync_sglist(ahc, scb, BUS_DMASYNC_POSTWRITE);
	if (cmd->use_sg != 0) {
		struct scatterlist *sg;

		sg = (struct scatterlist *)cmd->request_buffer;
		pci_unmap_sg(ahc->dev_softc, sg, cmd->use_sg,
			     scsi_to_pci_dma_dir(cmd->sc_data_direction));
	} else if (cmd->request_bufflen != 0) {
		pci_unmap_single(ahc->dev_softc,
				 scb->platform_data->buf_busaddr,
				 cmd->request_bufflen,
				 scsi_to_pci_dma_dir(cmd->sc_data_direction));
	}
}

static __inline int
ahc_linux_map_seg(struct ahc_softc *ahc, struct scb *scb,
		  struct ahc_dma_seg *sg, bus_addr_t addr, bus_size_t len)
{
	int	 consumed;

	if ((scb->sg_count + 1) > AHC_NSEG)
		panic("Too few segs for dma mapping.  "
		      "Increase AHC_NSEG\n");

	consumed = 1;
	sg->addr = ahc_htole32(addr & 0xFFFFFFFF);
	scb->platform_data->xfer_len += len;
	if (sizeof(bus_addr_t) > 4
	 && (ahc->flags & AHC_39BIT_ADDRESSING) != 0) {
		/*
		 * Due to DAC restrictions, we can't
		 * cross a 4GB boundary.
		 */
		if ((addr ^ (addr + len - 1)) & ~0xFFFFFFFF) {
			struct	 ahc_dma_seg *next_sg;
			uint32_t next_len;

			printf("Crossed Seg\n");
			if ((scb->sg_count + 2) > AHC_NSEG)
				panic("Too few segs for dma mapping.  "
				      "Increase AHC_NSEG\n");

			consumed++;
			next_sg = sg + 1;
			next_sg->addr = 0;
			next_len = (uint32_t)((-addr) & 0xFFFFFFFF);
			len -= next_len;
			next_len |= ((addr >> 8) + 0x1000000) & 0x7F000000;
			next_sg->len = ahc_htole32(next_len);
		}
		len |= (addr >> 8) & 0x7F000000;
	}
	sg->len = ahc_htole32(len);
	return (consumed);
}

/**************************** Tasklet Handler *********************************/

static void
ahc_runq_tasklet(unsigned long data)
{
	struct ahc_softc* ahc;
	struct ahc_linux_device *dev;
	u_long flags;

	ahc = (struct ahc_softc *)data;
	ahc_lock(ahc, &flags);
	while ((dev = ahc_linux_next_device_to_run(ahc)) != NULL) {
	
		TAILQ_REMOVE(&ahc->platform_data->device_runq, dev, links);
		dev->flags &= ~AHC_DEV_ON_RUN_LIST;
		ahc_linux_check_device_queue(ahc, dev);
		/* Yeild to our interrupt handler */
		ahc_unlock(ahc, &flags);
		ahc_lock(ahc, &flags);
	}
	ahc_unlock(ahc, &flags);
}

/************************ Shutdown/halt/reboot hook ***************************/
#include <xen/notifier.h>
#include <xen/reboot.h>

#if XEN_KILLED
static struct notifier_block ahc_linux_notifier = {
	ahc_linux_halt, NULL, 0
};

static int ahc_linux_halt(struct notifier_block *nb, u_long event, void *buf)
{
	struct ahc_softc *ahc;

	if (event == SYS_DOWN || event == SYS_HALT) {
		TAILQ_FOREACH(ahc, &ahc_tailq, links) {
			ahc_shutdown(ahc);
		}
	}
	return (NOTIFY_OK);
}
#endif

/******************************** Macros **************************************/
#define BUILD_SCSIID(ahc, cmd)						\
	((((cmd)->target << TID_SHIFT) & TID)				\
	| (((cmd)->channel == 0) ? (ahc)->our_id : (ahc)->our_id_b)	\
	| (((cmd)->channel == 0) ? 0 : TWIN_CHNLB))

/******************************** Bus DMA *************************************/
int
ahc_dma_tag_create(struct ahc_softc *ahc, bus_dma_tag_t parent,
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
ahc_dma_tag_destroy(struct ahc_softc *ahc, bus_dma_tag_t dmat)
{
	free(dmat, M_DEVBUF);
}

int
ahc_dmamem_alloc(struct ahc_softc *ahc, bus_dma_tag_t dmat, void** vaddr,
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
	if (ahc->dev_softc != NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,3)
		pci_set_dma_mask(ahc->dev_softc, 0xFFFFFFFF);
#else
		ahc->dev_softc->dma_mask = 0xFFFFFFFF;
#endif
	}
	*vaddr = pci_alloc_consistent(ahc->dev_softc,
				      dmat->maxsize, &map->bus_addr);
	if (ahc->dev_softc != NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,3)
		pci_set_dma_mask(ahc->dev_softc,
				 ahc->platform_data->hw_dma_mask);
#else
		ahc->dev_softc->dma_mask = ahc->platform_data->hw_dma_mask;
#endif
	}
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
ahc_dmamem_free(struct ahc_softc *ahc, bus_dma_tag_t dmat,
		void* vaddr, bus_dmamap_t map)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	pci_free_consistent(ahc->dev_softc, dmat->maxsize,
			    vaddr, map->bus_addr);
#else
	free(vaddr, M_DEVBUF);
#endif
}

int
ahc_dmamap_load(struct ahc_softc *ahc, bus_dma_tag_t dmat, bus_dmamap_t map,
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
	stack_sg.ds_addr = VIRT_TO_BUS(buf);
#endif
	stack_sg.ds_len = dmat->maxsize;
	cb(cb_arg, &stack_sg, /*nseg*/1, /*error*/0);
	return (0);
}

void
ahc_dmamap_destroy(struct ahc_softc *ahc, bus_dma_tag_t dmat, bus_dmamap_t map)
{
	/*
	 * The map may is NULL in our < 2.3.X implementation.
	 */
	if (map != NULL)
		free(map, M_DEVBUF);
}

int
ahc_dmamap_unload(struct ahc_softc *ahc, bus_dma_tag_t dmat, bus_dmamap_t map)
{
	/* Nothing to do */
	return (0);
}

/********************* Platform Dependent Functions ***************************/
int
ahc_softc_comp(struct ahc_softc *lahc, struct ahc_softc *rahc)
{
	int	value;
	int	rvalue;
	int	lvalue;

	/*
	 * Under Linux, cards are ordered as follows:
	 *	1) VLB/EISA BIOS enabled devices sorted by BIOS address.
	 *	2) PCI devices with BIOS enabled sorted by bus/slot/func.
	 *	3) All remaining VLB/EISA devices sorted by ioport.
	 *	4) All remaining PCI devices sorted by bus/slot/func.
	 */
	value = (lahc->flags & AHC_BIOS_ENABLED)
	      - (rahc->flags & AHC_BIOS_ENABLED);
	if (value != 0)
		/* Controllers with BIOS enabled have a *higher* priority */
		return (-value);

	/*
	 * Same BIOS setting, now sort based on bus type.
	 * EISA and VL controllers sort together.  EISA/VL
	 * have higher priority than PCI.
	 */
	rvalue = (rahc->chip & AHC_BUS_MASK);
 	if (rvalue == AHC_VL)
		rvalue = AHC_EISA;
	lvalue = (lahc->chip & AHC_BUS_MASK);
 	if (lvalue == AHC_VL)
		lvalue = AHC_EISA;
	value = lvalue - rvalue;
	if (value != 0)
		return (value);

	/* Still equal.  Sort by BIOS address, ioport, or bus/slot/func. */
	switch (rvalue) {
	case AHC_PCI:
	{
		char primary_channel;

		if (aic7xxx_reverse_scan != 0)
			value = ahc_get_pci_bus(rahc->dev_softc)
			      - ahc_get_pci_bus(lahc->dev_softc);
		else
			value = ahc_get_pci_bus(lahc->dev_softc)
			      - ahc_get_pci_bus(rahc->dev_softc);
		if (value != 0)
			break;
		if (aic7xxx_reverse_scan != 0)
			value = ahc_get_pci_slot(rahc->dev_softc)
			      - ahc_get_pci_slot(lahc->dev_softc);
		else
			value = ahc_get_pci_slot(lahc->dev_softc)
			      - ahc_get_pci_slot(rahc->dev_softc);
		if (value != 0)
			break;
		/*
		 * On multi-function devices, the user can choose
		 * to have function 1 probed before function 0.
		 * Give whichever channel is the primary channel
		 * the lowest priority.
		 */
		primary_channel = (lahc->flags & AHC_PRIMARY_CHANNEL) + 'A';
		value = 1;
		if (lahc->channel == primary_channel)
			value = -1;
		break;
	}
	case AHC_EISA:
		if ((rahc->flags & AHC_BIOS_ENABLED) != 0) {
			value = lahc->platform_data->bios_address
			      - rahc->platform_data->bios_address; 
		} else {
			value = lahc->bsh.ioport
			      - rahc->bsh.ioport; 
		}
		break;
	default:
		panic("ahc_softc_sort: invalid bus type");
	}
	return (value);
}

static void
ahc_linux_setup_tag_info(char *p, char *end)
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
			if ((targ >= AHC_NUM_TARGETS) ||
			    (instance >= NUM_ELEMENTS(aic7xxx_tag_info)))
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
			 && (instance < NUM_ELEMENTS(aic7xxx_tag_info))
			 && (targ < AHC_NUM_TARGETS)) {
				aic7xxx_tag_info[instance].tag_commands[targ] =
				    simple_strtoul(tok, NULL, 0) & 0xff;
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
 * ie. aic7xxx=stpwlev:1,extended
 */
int
aic7xxx_setup(char *s)
{
	int	i, n;
	char   *p;
	char   *end;

	static struct {
		const char *name;
		uint32_t *flag;
	} options[] = {
		{ "extended", &aic7xxx_extended },
		{ "no_reset", &aic7xxx_no_reset },
		{ "verbose", &aic7xxx_verbose },
		{ "reverse_scan", &aic7xxx_reverse_scan },
		{ "no_probe", &aic7xxx_no_probe },
		{ "periodic_otag", &aic7xxx_periodic_otag },
		{ "pci_parity", &aic7xxx_pci_parity },
		{ "seltime", &aic7xxx_seltime },
		{ "tag_info", NULL }
	};

	end = strchr(s, '\0');

	for (p = strtok(s, ",."); p; p = strtok(NULL, ",.")) {
		for (i = 0; i < NUM_ELEMENTS(options); i++) {
			n = strlen(options[i].name);

			if (strncmp(options[i].name, p, n) != 0)
				continue;

			if (strncmp(p, "tag_info", n) == 0) {
				ahc_linux_setup_tag_info(p + n, end);
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
__setup("aic7xxx=", aic7xxx_setup);
#endif

int aic7xxx_verbose;

/*
 * Try to detect an Adaptec 7XXX controller.
 */
int
ahc_linux_detect(Scsi_Host_Template *template)
{
	struct	ahc_softc *ahc;
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
	if (offsetof(struct ahc_cmd_internal, end)
	  > offsetof(struct scsi_cmnd, host_scribble)) {
		printf("ahc_linux_detect: SCSI data structures changed.\n");
		printf("ahc_linux_detect: Unable to attach\n");
		return (0);
	}
#ifdef MODULE
	/*
	 * If we've been passed any parameters, process them now.
	 */
	if (aic7xxx)
		aic7xxx_setup(aic7xxx);
	if (dummy_buffer[0] != 'P')
		printf(KERN_WARNING
"aic7xxx: Please read the file /usr/src/xen/drivers/scsi/README.aic7xxx\n"
"aic7xxx: to see the proper way to specify options to the aic7xxx module\n"
"aic7xxx: Specifically, don't use any commas when passing arguments to\n"
"aic7xxx: insmod or else it might trash certain memory areas.\n");
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
	template->proc_name = "aic7xxx";
#else
	template->proc_dir = &proc_scsi_aic7xxx;
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
	ahc_list_lockinit();

#ifdef CONFIG_PCI
	ahc_linux_pci_probe(template);
#endif

	if (aic7xxx_no_probe == 0)
		aic7770_linux_probe(template);

	/*
	 * Register with the SCSI layer all
	 * controllers we've found.
	 */
	spin_lock_irq(&io_request_lock);
	found = 0;
	TAILQ_FOREACH(ahc, &ahc_tailq, links) {

		if (ahc_linux_register_host(ahc, template) == 0)
			found++;
	}
	aic7xxx_detect_complete++;
	return (found);
}

int
ahc_linux_register_host(struct ahc_softc *ahc, Scsi_Host_Template *template)
{
	char  buf[80];
	struct Scsi_Host *host;
	char *new_name;
	u_long s;


	template->name = ahc->description;
	host = scsi_register(template, sizeof(struct ahc_softc *));
	if (host == NULL)
		return (ENOMEM);

	ahc_lock(ahc, &s);
	*((struct ahc_softc **)host->hostdata) = ahc;
	ahc->platform_data->host = host;
	host->can_queue = AHC_MAX_QUEUE;
	host->cmd_per_lun = 2;
	host->sg_tablesize = AHC_NSEG;
	host->select_queue_depths = ahc_linux_select_queue_depth;
	/* XXX No way to communicate the ID for multiple channels */
	host->this_id = ahc->our_id;
	host->irq = ahc->platform_data->irq;
	host->max_id = (ahc->features & AHC_WIDE) ? 16 : 8;
	host->max_lun = AHC_NUM_LUNS;
	host->max_channel = (ahc->features & AHC_TWIN) ? 1 : 0;
	ahc_set_unit(ahc, ahc_linux_next_unit());
	sprintf(buf, "scsi%d", host->host_no);
	new_name = malloc(strlen(buf) + 1, M_DEVBUF, M_NOWAIT);
	if (new_name != NULL) {
		strcpy(new_name, buf);
		ahc_set_name(ahc, new_name);
	}
	host->unique_id = ahc->unit;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4)
	scsi_set_pci_device(host, ahc->dev_softc);
#endif
	ahc_linux_initialize_scsi_bus(ahc);
	ahc_unlock(ahc, &s);
	return (0);
}

uint64_t
ahc_linux_get_memsize()
{
  //	struct sysinfo si;
  //
  //	si_meminfo(&si);
  //	return (si.totalram << PAGE_SHIFT);
  printf("JWS: aic7xxx: get_memsize\n");
  return 0;
}

/*
 * Find the smallest available unit number to use
 * for a new device.  We don't just use a static
 * count to handle the "repeated hot-(un)plug"
 * scenario.
 */
static int
ahc_linux_next_unit()
{
	struct ahc_softc *ahc;
	int unit;

	unit = 0;
retry:
	TAILQ_FOREACH(ahc, &ahc_tailq, links) {
		if (ahc->unit == unit) {
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
ahc_linux_initialize_scsi_bus(struct ahc_softc *ahc)
{
	int i;
	int numtarg;

	i = 0;
	numtarg = 0;

	if (aic7xxx_no_reset != 0)
		ahc->flags &= ~(AHC_RESET_BUS_A|AHC_RESET_BUS_B);

	if ((ahc->flags & AHC_RESET_BUS_A) != 0)
		ahc_reset_channel(ahc, 'A', /*initiate_reset*/TRUE);
	else
		numtarg = (ahc->features & AHC_WIDE) ? 16 : 8;

	if ((ahc->features & AHC_TWIN) != 0) {

		if ((ahc->flags & AHC_RESET_BUS_B) != 0) {
			ahc_reset_channel(ahc, 'B', /*initiate_reset*/TRUE);
		} else {
			if (numtarg == 0)
				i = 8;
			numtarg += 8;
		}
	}

	for (; i < numtarg; i++) {
		struct ahc_devinfo devinfo;
		struct ahc_initiator_tinfo *tinfo;
		struct ahc_tmode_tstate *tstate;
		u_int our_id;
		u_int target_id;
		char channel;

		channel = 'A';
		our_id = ahc->our_id;
		target_id = i;
		if (i > 7 && (ahc->features & AHC_TWIN) != 0) {
			channel = 'B';
			our_id = ahc->our_id_b;
			target_id = i % 8;
		}
		tinfo = ahc_fetch_transinfo(ahc, channel, our_id,
					    target_id, &tstate);
		tinfo->goal = tinfo->user;
		/*
		 * Don't try negotiations that require PPR messages
		 * until we successfully retrieve Inquiry data.
		 */
		tinfo->goal.ppr_options = 0;
		if (tinfo->goal.transport_version > SCSI_REV_2)
			tinfo->goal.transport_version = SCSI_REV_2;
		ahc_compile_devinfo(&devinfo, our_id, target_id,
				   CAM_LUN_WILDCARD, channel, ROLE_INITIATOR);
		ahc_update_neg_request(ahc, &devinfo, tstate,
				       tinfo, /*force*/FALSE);
	}
	/* Give the bus some time to recover */
	if ((ahc->flags & (AHC_RESET_BUS_A|AHC_RESET_BUS_B)) != 0) {	  
	  // JWS - XEN - DONT USE TIMERS HERE
#if 0
		ahc_linux_freeze_sim_queue(ahc);
		init_timer(&ahc->platform_data->reset_timer);
		ahc->platform_data->reset_timer.data = (u_long)ahc;
		ahc->platform_data->reset_timer.expires =
		    jiffies + (AIC7XXX_RESET_DELAY * HZ)/1000;
		ahc->platform_data->reset_timer.function =
		    ahc_linux_release_sim_queue;
		add_timer(&ahc->platform_data->reset_timer);
#else
	  mdelay(AIC7XXX_RESET_DELAY);
#endif	  
	}
}

int
ahc_platform_alloc(struct ahc_softc *ahc, void *platform_arg)
{
	ahc->platform_data =
	    malloc(sizeof(struct ahc_platform_data), M_DEVBUF, M_NOWAIT);
	if (ahc->platform_data == NULL)
		return (ENOMEM);
	memset(ahc->platform_data, 0, sizeof(struct ahc_platform_data));
	TAILQ_INIT(&ahc->platform_data->completeq);
	TAILQ_INIT(&ahc->platform_data->device_runq);
	ahc->platform_data->irq = AHC_LINUX_NOIRQ;
	ahc->platform_data->hw_dma_mask = 0xFFFFFFFF;
	ahc_lockinit(ahc);
	ahc_done_lockinit(ahc);
#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	init_MUTEX_LOCKED(&ahc->platform_data->eh_sem);
#else
	ahc->platform_data->eh_sem = MUTEX_LOCKED;
#endif
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	tasklet_init(&ahc->platform_data->runq_tasklet, ahc_runq_tasklet,
		     (unsigned long)ahc);
#endif
	ahc->seltime = (aic7xxx_seltime & 0x3) << 4;
	ahc->seltime_b = (aic7xxx_seltime & 0x3) << 4;
#if XEN_KILLED
	if (TAILQ_EMPTY(&ahc_tailq))
		register_reboot_notifier(&ahc_linux_notifier);
#endif
	return (0);
}

void
ahc_platform_free(struct ahc_softc *ahc)
{
	if (ahc->platform_data != NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		tasklet_kill(&ahc->platform_data->runq_tasklet);
#endif
		if (ahc->platform_data->host != NULL)
			scsi_unregister(ahc->platform_data->host);
		if (ahc->platform_data->irq != AHC_LINUX_NOIRQ)
			free_irq(ahc->platform_data->irq, ahc);
		if (ahc->tag == BUS_SPACE_PIO
		 && ahc->bsh.ioport != 0)
			release_region(ahc->bsh.ioport, 256);
		if (ahc->tag == BUS_SPACE_MEMIO
		 && ahc->bsh.maddr != NULL) {
			u_long base_addr;

			base_addr = (u_long)ahc->bsh.maddr;
			base_addr &= PAGE_MASK;
			iounmap((void *)base_addr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
			release_mem_region(ahc->platform_data->mem_busaddr,
					   0x1000);
#endif
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		/* XXX Need an instance detach in the PCI code */
		if (ahc->dev_softc != NULL)
			ahc->dev_softc->driver = NULL;
#endif
		free(ahc->platform_data, M_DEVBUF);
	}
	if (TAILQ_EMPTY(&ahc_tailq)) {
#ifdef XEN_KILLED
	  unregister_reboot_notifier(&ahc_linux_notifier);
#endif
#ifdef CONFIG_PCI
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		pci_unregister_driver(&aic7xxx_pci_driver);
#endif
#endif
	}
}

void
ahc_platform_freeze_devq(struct ahc_softc *ahc, struct scb *scb)
{
	ahc_platform_abort_scbs(ahc, SCB_GET_TARGET(ahc, scb),
				SCB_GET_CHANNEL(ahc, scb),
				SCB_GET_LUN(scb), SCB_LIST_NULL,
				ROLE_UNKNOWN, CAM_REQUEUE_REQ);
}

void
ahc_platform_set_tags(struct ahc_softc *ahc, struct ahc_devinfo *devinfo,
		      ahc_queue_alg alg)
{
	struct ahc_linux_device *dev;
	int was_queuing;
	int now_queuing;

	dev = ahc_linux_get_device(ahc, devinfo->channel - 'A',
				   devinfo->target,
				   devinfo->lun, /*alloc*/FALSE);
	if (dev == NULL)
		return;
	was_queuing = dev->flags & (AHC_DEV_Q_BASIC|AHC_DEV_Q_TAGGED);
	now_queuing = alg != AHC_QUEUE_NONE;
	if ((dev->flags & AHC_DEV_FREEZE_TIL_EMPTY) == 0
	 && (was_queuing != now_queuing)
	 && (dev->active != 0)) {
		dev->flags |= AHC_DEV_FREEZE_TIL_EMPTY;
		dev->qfrozen++;
	}

	dev->flags &= ~(AHC_DEV_Q_BASIC|AHC_DEV_Q_TAGGED|AHC_DEV_PERIODIC_OTAG);
	if (now_queuing) {
		u_int usertags;

		usertags = ahc_linux_user_tagdepth(ahc, devinfo);
		if (!was_queuing) {
			/*
			 * Start out agressively and allow our
			 * dynamic queue depth algorithm to take
			 * care of the rest.
			 */
			dev->maxtags = usertags;
			dev->openings = dev->maxtags - dev->active;
		}
		if (alg == AHC_QUEUE_TAGGED) {
			dev->flags |= AHC_DEV_Q_TAGGED;
			if (aic7xxx_periodic_otag != 0)
				dev->flags |= AHC_DEV_PERIODIC_OTAG;
		} else
			dev->flags |= AHC_DEV_Q_BASIC;
	} else {
		/* We can only have one opening. */
		dev->maxtags = 0;
		dev->openings =  1 - dev->active;
	}
}

int
ahc_platform_abort_scbs(struct ahc_softc *ahc, int target, char channel,
			int lun, u_int tag, role_t role, uint32_t status)
{
	int chan;
	int maxchan;
	int targ;
	int maxtarg;
	int clun;
	int maxlun;
	int count;

	if (tag != SCB_LIST_NULL)
		return (0);

	chan = 0;
	if (channel != ALL_CHANNELS) {
		chan = channel - 'A';
		maxchan = chan + 1;
	} else {
		maxchan = (ahc->features & AHC_TWIN) ? 2 : 1;
	}
	targ = 0;
	if (target != CAM_TARGET_WILDCARD) {
		targ = target;
		maxtarg = targ + 1;
	} else {
		maxtarg = (ahc->features & AHC_WIDE) ? 16 : 8;
	}
	clun = 0;
	if (lun != CAM_LUN_WILDCARD) {
		clun = lun;
		maxlun = clun + 1;
	} else {
		maxlun = AHC_NUM_LUNS;
	}

	count = 0;
	for (; chan < maxchan; chan++) {

		for (; targ < maxtarg; targ++) {

			for (; clun < maxlun; clun++) {
				struct ahc_linux_device *dev;
				struct ahc_busyq *busyq;
				struct ahc_cmd *acmd;

				dev = ahc_linux_get_device(ahc, chan,
							   targ, clun,
							   /*alloc*/FALSE);
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
					ahc_linux_queue_cmd_complete(ahc, cmd);
				}
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
ahc_linux_select_queue_depth(struct Scsi_Host * host,
			     Scsi_Device * scsi_devs)
{
	Scsi_Device *device;
	struct	ahc_softc *ahc;
	u_long	flags;
	int	scbnum;

	ahc = *((struct ahc_softc **)host->hostdata);
	ahc_lock(ahc, &flags);
	scbnum = 0;
	for (device = scsi_devs; device != NULL; device = device->next) {
		if (device->host == host) {
			ahc_linux_device_queue_depth(ahc, device);
			scbnum += device->queue_depth;
		}
	}
	ahc_unlock(ahc, &flags);
}

static u_int
ahc_linux_user_tagdepth(struct ahc_softc *ahc, struct ahc_devinfo *devinfo)
{
	static int warned_user;
	u_int tags;

	tags = 0;
	if ((ahc->user_discenable & devinfo->target_mask) != 0) {
		if (warned_user == 0
		 && ahc->unit >= NUM_ELEMENTS(aic7xxx_tag_info)) {

			printf("aic7xxx: WARNING, insufficient "
			       "tag_info instances for installed "
			       "controllers. Using defaults\n");
			printf("aic7xxx: Please update the "
			       "aic7xxx_tag_info array in the "
			       "aic7xxx.c source file.\n");
			tags = AHC_MAX_QUEUE;
			warned_user++;
		} else {
			adapter_tag_info_t *tag_info;

			tag_info = &aic7xxx_tag_info[ahc->unit];
			tags = tag_info->tag_commands[devinfo->target_offset];
			if (tags > AHC_MAX_QUEUE)
				tags = AHC_MAX_QUEUE;
		}
	}
	return (tags);
}

/*
 * Determines the queue depth for a given device.
 */
static void
ahc_linux_device_queue_depth(struct ahc_softc *ahc, Scsi_Device * device)
{
	struct	ahc_devinfo devinfo;
	u_int	tags;

	ahc_compile_devinfo(&devinfo,
			    device->channel == 0 ? ahc->our_id : ahc->our_id_b,
			    device->id, device->lun,
			    device->channel == 0 ? 'A' : 'B',
			    ROLE_INITIATOR);
	tags = ahc_linux_user_tagdepth(ahc, &devinfo);
	if (tags != 0
	 && device->tagged_supported != 0) {

		device->queue_depth = tags;
		ahc_set_tags(ahc, &devinfo, AHC_QUEUE_TAGGED);
		printf("scsi%d:%c:%d:%d: Tagged Queuing enabled.  Depth %d\n",
	       	       ahc->platform_data->host->host_no, devinfo.channel,
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
ahc_linux_queue(Scsi_Cmnd * cmd, void (*scsi_done) (Scsi_Cmnd *))
{
	struct	 ahc_softc *ahc;
	struct	 ahc_linux_device *dev;
	u_long	 flags;

	ahc = *(struct ahc_softc **)cmd->host->hostdata;

	/*
	 * Save the callback on completion function.
	 */
	cmd->scsi_done = scsi_done;

	ahc_lock(ahc, &flags);
	dev = ahc_linux_get_device(ahc, cmd->channel, cmd->target,
				   cmd->lun, /*alloc*/TRUE);
	if (dev == NULL) {
		ahc_unlock(ahc, &flags);
		printf("aic7xxx_linux_queue: Unable to allocate device!\n");
		return (-ENOMEM);
	}
	cmd->result = CAM_REQ_INPROG << 16;
	TAILQ_INSERT_TAIL(&dev->busyq, (struct ahc_cmd *)cmd, acmd_links.tqe);
	if ((dev->flags & AHC_DEV_ON_RUN_LIST) == 0) {
		TAILQ_INSERT_TAIL(&ahc->platform_data->device_runq, dev, links);
		dev->flags |= AHC_DEV_ON_RUN_LIST;
		ahc_linux_run_device_queues(ahc);
	}
	ahc_unlock(ahc, &flags);
	return (0);
}

static void
ahc_linux_run_device_queue(struct ahc_softc *ahc, struct ahc_linux_device *dev)
{
	struct	 ahc_cmd *acmd;
	struct	 scsi_cmnd *cmd;
	struct	 scb *scb;
	struct	 hardware_scb *hscb;
	struct	 ahc_initiator_tinfo *tinfo;
	struct	 ahc_tmode_tstate *tstate;
	uint16_t mask;

	if ((dev->flags & AHC_DEV_ON_RUN_LIST) != 0)
		panic("running device on run list");

	while ((acmd = TAILQ_FIRST(&dev->busyq)) != NULL
	    && dev->openings > 0 && dev->qfrozen == 0) {

		/*
		 * Schedule us to run later.  The only reason we are not
		 * running is because the whole controller Q is frozen.
		 */
		if (ahc->platform_data->qfrozen != 0) {

			TAILQ_INSERT_TAIL(&ahc->platform_data->device_runq,
					  dev, links);
			dev->flags |= AHC_DEV_ON_RUN_LIST;
			return;
		}
		/*
		 * Get an scb to use.
		 */
		if ((scb = ahc_get_scb(ahc)) == NULL) {
			TAILQ_INSERT_TAIL(&ahc->platform_data->device_runq,
					 dev, links);
			dev->flags |= AHC_DEV_ON_RUN_LIST;
			ahc->flags |= AHC_RESOURCE_SHORTAGE;
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
		hscb->scsiid = BUILD_SCSIID(ahc, cmd);
		hscb->lun = cmd->lun;
		mask = SCB_GET_TARGET_MASK(ahc, scb);
		tinfo = ahc_fetch_transinfo(ahc, SCB_GET_CHANNEL(ahc, scb),
					    SCB_GET_OUR_ID(scb),
					    SCB_GET_TARGET(ahc, scb), &tstate);
		hscb->scsirate = tinfo->scsirate;
		hscb->scsioffset = tinfo->curr.offset;
		if ((tstate->ultraenb & mask) != 0)
			hscb->control |= ULTRAENB;

		if ((ahc->user_discenable & mask) != 0)
			hscb->control |= DISCENB;

		if ((tstate->auto_negotiate & mask) != 0) {
			scb->flags |= SCB_AUTO_NEGOTIATE;
			scb->hscb->control |= MK_MESSAGE;
		}

		if ((dev->flags & (AHC_DEV_Q_TAGGED|AHC_DEV_Q_BASIC)) != 0) {
			if (dev->commands_since_idle_or_otag == AHC_OTAG_THRESH
			 && (dev->flags & AHC_DEV_Q_TAGGED) != 0) {
				hscb->control |= MSG_ORDERED_TASK;
				dev->commands_since_idle_or_otag = 0;
			} else {
				hscb->control |= MSG_SIMPLE_TASK;
			}
		}

		hscb->cdb_len = cmd->cmd_len;
		if (hscb->cdb_len <= 12) {
			memcpy(hscb->shared_data.cdb, cmd->cmnd, hscb->cdb_len);
		} else {
			memcpy(hscb->cdb32, cmd->cmnd, hscb->cdb_len);
			scb->flags |= SCB_CDB32_PTR;
		}

		scb->platform_data->xfer_len = 0;
		ahc_set_residual(scb, 0);
		ahc_set_sense_residual(scb, 0);
		scb->sg_count = 0;
		if (cmd->use_sg != 0) {
			struct	ahc_dma_seg *sg;
			struct	scatterlist *cur_seg;
			struct	scatterlist *end_seg;
			int	nseg;

			cur_seg = (struct scatterlist *)cmd->request_buffer;
			nseg = pci_map_sg(ahc->dev_softc, cur_seg, cmd->use_sg,
				 scsi_to_pci_dma_dir(cmd ->sc_data_direction));
			end_seg = cur_seg + nseg;
			/* Copy the segments into the SG list. */
			sg = scb->sg_list;
			/*
			 * The sg_count may be larger than nseg if
			 * a transfer crosses a 32bit page.
			 */ 
			while (cur_seg < end_seg) {
				bus_addr_t addr;
				bus_size_t len;
				int consumed;

				addr = sg_dma_address(cur_seg);
				len = sg_dma_len(cur_seg);
				consumed = ahc_linux_map_seg(ahc, scb,
							     sg, addr, len);
				sg += consumed;
				scb->sg_count += consumed;
				cur_seg++;
			}
			sg--;
			sg->len |= ahc_htole32(AHC_DMA_LAST_SEG);

			/*
			 * Reset the sg list pointer.
			 */
			scb->hscb->sgptr =
			    ahc_htole32(scb->sg_list_phys | SG_FULL_RESID);

			/*
			 * Copy the first SG into the "current"
			 * data pointer area.
			 */
			scb->hscb->dataptr = scb->sg_list->addr;
			scb->hscb->datacnt = scb->sg_list->len;
		} else if (cmd->request_bufflen != 0) {
			struct	 ahc_dma_seg *sg;
			bus_addr_t addr;

			sg = scb->sg_list;
			addr = pci_map_single(ahc->dev_softc,
			       cmd->request_buffer,
			       cmd->request_bufflen,
			       scsi_to_pci_dma_dir(cmd->sc_data_direction));
			scb->platform_data->buf_busaddr = addr;
			scb->sg_count = ahc_linux_map_seg(ahc, scb,
							  sg, addr,
							  cmd->request_bufflen);
			sg->len |= ahc_htole32(AHC_DMA_LAST_SEG);

			/*
			 * Reset the sg list pointer.
			 */
			scb->hscb->sgptr =
			    ahc_htole32(scb->sg_list_phys | SG_FULL_RESID);

			/*
			 * Copy the first SG into the "current"
			 * data pointer area.
			 */
			scb->hscb->dataptr = sg->addr;
			scb->hscb->datacnt = sg->len;
		} else {
			scb->hscb->sgptr = ahc_htole32(SG_LIST_NULL);
			scb->hscb->dataptr = 0;
			scb->hscb->datacnt = 0;
			scb->sg_count = 0;
		}

		ahc_sync_sglist(ahc, scb, BUS_DMASYNC_PREWRITE);
		LIST_INSERT_HEAD(&ahc->pending_scbs, scb, pending_links);
		dev->openings--;
		dev->active++;
		dev->commands_issued++;
		if ((dev->flags & AHC_DEV_PERIODIC_OTAG) != 0)
			dev->commands_since_idle_or_otag++;

		/*
		 * We only allow one untagged transaction
		 * per target in the initiator role unless
		 * we are storing a full busy target *lun*
		 * table in SCB space.
		 */
		if ((scb->hscb->control & (TARGET_SCB|TAG_ENB)) == 0
		 && (ahc->features & AHC_SCB_BTT) == 0) {
			struct scb_tailq *untagged_q;
			int target_offset;

			target_offset = SCB_GET_TARGET_OFFSET(ahc, scb);
			untagged_q = &(ahc->untagged_queues[target_offset]);
			TAILQ_INSERT_TAIL(untagged_q, scb, links.tqe);
			scb->flags |= SCB_UNTAGGEDQ;
			if (TAILQ_FIRST(untagged_q) != scb)
				continue;
		}
		scb->flags |= SCB_ACTIVE;
		ahc_queue_scb(ahc, scb);
	}
}

/*
 * SCSI controller interrupt handler.
 */
void
ahc_linux_isr(int irq, void *dev_id, struct pt_regs * regs)
{
	struct	ahc_softc *ahc;
	struct	ahc_cmd *acmd;
	u_long	flags;
	struct	ahc_linux_device *next_dev;

	ahc = (struct ahc_softc *) dev_id;
	ahc_lock(ahc, &flags); 
	ahc_intr(ahc);
	acmd = TAILQ_FIRST(&ahc->platform_data->completeq);
	TAILQ_INIT(&ahc->platform_data->completeq);
	next_dev = ahc_linux_next_device_to_run(ahc);
	ahc_unlock(ahc, &flags);
	if (next_dev) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		tasklet_schedule(&ahc->platform_data->runq_tasklet);
#else
		ahc_runq_tasklet((unsigned long)ahc);
#endif
	}
	if (acmd != NULL)
		ahc_linux_run_complete_queue(ahc, acmd);
}

void
ahc_platform_flushwork(struct ahc_softc *ahc)
{
	struct ahc_cmd *acmd;

	acmd = TAILQ_FIRST(&ahc->platform_data->completeq);
	TAILQ_INIT(&ahc->platform_data->completeq);
	if (acmd != NULL)
		ahc_linux_run_complete_queue(ahc, acmd);
}

static struct ahc_linux_target*
ahc_linux_alloc_target(struct ahc_softc *ahc, u_int channel, u_int target)
{
	struct ahc_linux_target *targ;
	u_int target_offset;

	targ = malloc(sizeof(*targ), M_DEVBUG, M_NOWAIT);
	if (targ == NULL)
		return (NULL);
	memset(targ, 0, sizeof(*targ));
	targ->channel = channel;
	targ->target = target;
	targ->ahc = ahc;
	target_offset = target;
	if (channel != 0)
		target_offset += 8;
	ahc->platform_data->targets[target_offset] = targ;
	return (targ);
}

static void
ahc_linux_free_target(struct ahc_softc *ahc, struct ahc_linux_target *targ)
{
	u_int target_offset;

	target_offset = targ->target;
	if (targ->channel != 0)
		target_offset += 8;
	ahc->platform_data->targets[target_offset] = NULL;
	free(targ, M_DEVBUF);
}

static struct ahc_linux_device*
ahc_linux_alloc_device(struct ahc_softc *ahc,
		 struct ahc_linux_target *targ, u_int lun)
{
	struct ahc_linux_device *dev;

	dev = malloc(sizeof(*dev), M_DEVBUG, M_NOWAIT);
	if (dev == NULL)
		return (NULL);
	memset(dev, 0, sizeof(*dev));
	init_timer(&dev->timer);
	TAILQ_INIT(&dev->busyq);
	dev->flags = AHC_DEV_UNCONFIGURED;
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
ahc_linux_free_device(struct ahc_softc *ahc, struct ahc_linux_device *dev)
{
	struct ahc_linux_target *targ;

	del_timer(&dev->timer);
	targ = dev->target;
	targ->devices[dev->lun] = NULL;
	free(dev, M_DEVBUF);
	targ->refcount--;
	if (targ->refcount == 0)
		ahc_linux_free_target(ahc, targ);
}

/*
 * Return a string describing the driver.
 */
const char *
ahc_linux_info(struct Scsi_Host *host)
{
	static char buffer[512];
	char	ahc_info[256];
	char   *bp;
	struct ahc_softc *ahc;

	bp = &buffer[0];
	ahc = *(struct ahc_softc **)host->hostdata;
	memset(bp, 0, sizeof(buffer));
	strcpy(bp, "Adaptec AIC7XXX EISA/VLB/PCI SCSI HBA DRIVER, Rev ");
	strcat(bp, AIC7XXX_DRIVER_VERSION);
	strcat(bp, "\n");
	strcat(bp, "        <");
	strcat(bp, ahc->description);
	strcat(bp, ">\n");
	strcat(bp, "        ");
	ahc_controller_info(ahc, ahc_info);
	strcat(bp, ahc_info);
	strcat(bp, "\n");

	return (bp);
}

void
ahc_send_async(struct ahc_softc *ahc, char channel,
	       u_int target, u_int lun, ac_code code, void *arg)
{
	switch (code) {
	case AC_TRANSFER_NEG:
	{
		char	buf[80];
		struct	ahc_linux_target *targ;
		struct	info_str info;
		struct	ahc_initiator_tinfo *tinfo;
		struct	ahc_tmode_tstate *tstate;
		int	target_offset;

		info.buffer = buf;
		info.length = sizeof(buf);
		info.offset = 0;
		info.pos = 0;
		tinfo = ahc_fetch_transinfo(ahc, channel,
						channel == 'A' ? ahc->our_id
							       : ahc->our_id_b,
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
		target_offset = target;
		if (channel == 'B')
			target_offset += 8;
		targ = ahc->platform_data->targets[target_offset];
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

		printf("(%s:%c:", ahc_name(ahc), channel);
		if (target == CAM_TARGET_WILDCARD)
			printf("*): ");
		else
			printf("%d): ", target);
		ahc_format_transinfo(&info, &tinfo->curr);
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
		if (ahc->platform_data->host != NULL) {
			scsi_report_bus_reset(ahc->platform_data->host,
					      channel - 'A');
		}
#endif
                break;
        default:
                panic("ahc_send_async: Unexpected async event");
        }
}

/*
 * Calls the higher level scsi done function and frees the scb.
 */
void
ahc_done(struct ahc_softc *ahc, struct scb * scb)
{
	Scsi_Cmnd *cmd;
	struct ahc_linux_device *dev;

	LIST_REMOVE(scb, pending_links);
	if ((scb->flags & SCB_UNTAGGEDQ) != 0) {
		struct scb_tailq *untagged_q;
		int target_offset;

		target_offset = SCB_GET_TARGET_OFFSET(ahc, scb);
		untagged_q = &(ahc->untagged_queues[target_offset]);
		TAILQ_REMOVE(untagged_q, scb, links.tqe);
		ahc_run_untagged_queue(ahc, untagged_q);
	}

	if ((scb->flags & SCB_ACTIVE) == 0) {
		printf("SCB %d done'd twice\n", scb->hscb->tag);
		ahc_dump_card_state(ahc);
		panic("Stopping for safety");
	}
	cmd = scb->io_ctx;
	dev = scb->platform_data->dev;
	dev->active--;
	dev->openings++;
	ahc_linux_unmap_scb(ahc, scb);
	if (scb->flags & SCB_SENSE) {
		memcpy(cmd->sense_buffer, ahc_get_sense_buf(ahc, scb),
		       MIN(sizeof(struct scsi_sense_data),
			   sizeof(cmd->sense_buffer)));
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
	if (ahc_get_transaction_status(scb) == CAM_REQ_INPROG) {
		uint32_t amount_xferred;

		amount_xferred =
		    ahc_get_transfer_length(scb) - ahc_get_residual(scb);
		if (amount_xferred < scb->io_ctx->underflow) {
			printf("Saw underflow (%ld of %ld bytes). "
			       "Treated as error\n",
				ahc_get_residual(scb),
				ahc_get_transfer_length(scb));
			ahc_set_transaction_status(scb, CAM_DATA_RUN_ERR);
		} else {
			ahc_set_transaction_status(scb, CAM_REQ_CMP);
			ahc_linux_sniff_command(ahc, cmd, scb);
		}
	} else if (ahc_get_transaction_status(scb) == DID_OK) {
		ahc_linux_handle_scsi_status(ahc, dev, scb);
	} else if (ahc_get_transaction_status(scb) == DID_NO_CONNECT) {
		/*
		 * Should a selection timeout kill the device?
		 * That depends on whether the selection timeout
		 * is persistent.  Since we have no guarantee that
		 * the mid-layer will issue an inquiry for this device
		 * again, we can't just kill it off.
		dev->flags |= AHC_DEV_UNCONFIGURED;
		 */
	}

	if (dev->openings == 1
	 && ahc_get_transaction_status(scb) == CAM_REQ_CMP
	 && ahc_get_scsi_status(scb) != SCSI_STATUS_QUEUE_FULL)
		dev->tag_success_count++;
	/*
	 * Some devices deal with temporary internal resource
	 * shortages by returning queue full.  When the queue
	 * full occurrs, we throttle back.  Slowly try to get
	 * back to our previous queue depth.
	 */
	if ((dev->openings + dev->active) < dev->maxtags
	 && dev->tag_success_count > AHC_TAG_SUCCESS_INTERVAL) {
		dev->tag_success_count = 0;
		dev->openings++;
	}

	if (dev->active == 0)
		dev->commands_since_idle_or_otag = 0;

	if (TAILQ_EMPTY(&dev->busyq)) {
		if ((dev->flags & AHC_DEV_UNCONFIGURED) != 0
		 && dev->active == 0)
			ahc_linux_free_device(ahc, dev);
	} else if ((dev->flags & AHC_DEV_ON_RUN_LIST) == 0) {
		TAILQ_INSERT_TAIL(&ahc->platform_data->device_runq, dev, links);
		dev->flags |= AHC_DEV_ON_RUN_LIST;
	}

	if ((scb->flags & SCB_RECOVERY_SCB) != 0) {
		printf("Recovery SCB completes\n");
#if 0
		up(&ahc->platform_data->eh_sem);
#endif
	}

	ahc_free_scb(ahc, scb);
	ahc_linux_queue_cmd_complete(ahc, cmd);
}

static void
ahc_linux_handle_scsi_status(struct ahc_softc *ahc,
			     struct ahc_linux_device *dev, struct scb *scb)
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
	switch (ahc_get_scsi_status(scb)) {
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
/*
			ahc_print_path(ahc, scb);
			printf("Dropping tag count to %d\n", dev->active);
 */
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
				 == AHC_LOCK_TAGS_COUNT) {
					dev->maxtags = dev->active;
					ahc_print_path(ahc, scb);
					printf("Locking max tag count at %d\n",
					       dev->active);
				}
			} else {
				dev->tags_on_last_queuefull = dev->active;
				dev->last_queuefull_same_count = 0;
			}
			ahc_set_transaction_status(scb, CAM_REQUEUE_REQ);
			ahc_set_scsi_status(scb, SCSI_STATUS_OK);
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
	{
		/*
		 * Set a short timer to defer sending commands for
		 * a bit since Linux will not delay in this case.
		 */
		if ((dev->flags & AHC_DEV_TIMER_ACTIVE) != 0) {
			printf("%s:%c:%d: Device Timer still active during "
			       "busy processing\n", ahc_name(ahc),
				dev->target->channel, dev->target->target);
			break;
		}
		dev->flags |= AHC_DEV_TIMER_ACTIVE;
		dev->qfrozen++;
		init_timer(&dev->timer);
		dev->timer.data = (u_long)dev;
		dev->timer.expires = jiffies + (HZ/2);
		dev->timer.function = ahc_linux_dev_timed_unfreeze;
		add_timer(&dev->timer);
		break;
	}
	}
}

static void
ahc_linux_filter_command(struct ahc_softc *ahc, Scsi_Cmnd *cmd, struct scb *scb)
{
	switch (cmd->cmnd[0]) {
	case INQUIRY:
	{
		struct	ahc_devinfo devinfo;
		struct	scsi_inquiry *inq;
		struct	scsi_inquiry_data *sid;
		struct	ahc_initiator_tinfo *tinfo;
		struct	ahc_transinfo *user;
		struct	ahc_transinfo *goal;
		struct	ahc_transinfo *curr;
		struct	ahc_tmode_tstate *tstate;
		struct	ahc_syncrate *syncrate;
		struct	ahc_linux_device *dev;
		u_int	scsiid;
		u_int	maxsync;
		int	transferred_len;
		int	minlen;
		u_int	width;
		u_int	period;
		u_int	offset;
		u_int	ppr_options;

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
			       ahc_name(ahc));
			break;
		}
		transferred_len = ahc_get_transfer_length(scb)
				- ahc_get_residual(scb);
		sid = (struct scsi_inquiry_data *)cmd->request_buffer;

		/*
		 * Determine if this lun actually exists.  If so,
		 * hold on to its corresponding device structure.
		 * If not, make sure we release the device and
		 * don't bother processing the rest of this inquiry
		 * command.
		 */
		dev = ahc_linux_get_device(ahc, cmd->channel,
					   cmd->target, cmd->lun,
					   /*alloc*/FALSE);
		if (transferred_len >= 1
		 && SID_QUAL(sid) == SID_QUAL_LU_CONNECTED) {

			dev->flags &= ~AHC_DEV_UNCONFIGURED;
		} else {
			dev->flags |= AHC_DEV_UNCONFIGURED;
			break;
		}

		/*
		 * Update our notion of this device's transfer
		 * negotiation capabilities.
		 */
		scsiid = BUILD_SCSIID(ahc, cmd);
		ahc_compile_devinfo(&devinfo, SCSIID_OUR_ID(scsiid),
				    cmd->target, cmd->lun,
				    SCSIID_CHANNEL(ahc, scsiid),
				    ROLE_INITIATOR);
		tinfo = ahc_fetch_transinfo(ahc, devinfo.channel,
					    devinfo.our_scsiid,
					    devinfo.target, &tstate);
		user = &tinfo->user;
		goal = &tinfo->goal;
		curr = &tinfo->curr;
		width = user->width;
		period = user->period;
		offset = user->offset;
		ppr_options = user->ppr_options;
		minlen = offsetof(struct scsi_inquiry_data, version) + 1;
		if (transferred_len >= minlen) {
			curr->protocol_version = SID_ANSI_REV(sid);

			/*
			 * Only attempt SPI3 once we've verified that
			 * the device claims to support SPI3 features.
			 */
			if (curr->protocol_version < SCSI_REV_2)
				curr->transport_version = SID_ANSI_REV(sid);
			else
				curr->transport_version = SCSI_REV_2;
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
			} else if ((goal->ppr_options & MSG_EXT_PPR_DT_REQ)== 0)
				ppr_options = 0;

			if (curr->protocol_version > SCSI_REV_2)
				curr->transport_version = 3;
		} else {
			ppr_options = 0;
		}
		ahc_validate_width(ahc, /*tinfo limit*/NULL, &width,
				   ROLE_UNKNOWN);
		if ((ahc->features & AHC_ULTRA2) != 0)
			maxsync = AHC_SYNCRATE_DT;
		else if ((ahc->features & AHC_ULTRA) != 0)
			maxsync = AHC_SYNCRATE_ULTRA;
		else
			maxsync = AHC_SYNCRATE_FAST;

		syncrate = ahc_find_syncrate(ahc, &period,
					     &ppr_options, maxsync);
		ahc_validate_offset(ahc, /*tinfo limit*/NULL, syncrate,
				    &offset, width, ROLE_UNKNOWN);
		if (offset == 0 || period == 0) {
			period = 0;
			offset = 0;
			ppr_options = 0;
		}
		/* Apply our filtered user settings. */
		ahc_set_width(ahc, &devinfo, width,
			      AHC_TRANS_GOAL, /*paused*/FALSE);
		ahc_set_syncrate(ahc, &devinfo, syncrate, period,
				 offset, ppr_options, AHC_TRANS_GOAL,
				 /*paused*/FALSE);
		break;
	}
	default:
		panic("ahc_linux_filter_command: Unexpected Command type  %x\n",
		      cmd->cmnd[0]);
		break;
	}
}

#if 0
static void
ahc_linux_sem_timeout(u_long arg)
{
	struct semaphore *sem;

	sem = (struct semaphore *)arg;
	up(sem);
}

static void
ahc_linux_freeze_sim_queue(struct ahc_softc *ahc)
{
	ahc->platform_data->qfrozen++;
	if (ahc->platform_data->qfrozen == 1)
		scsi_block_requests(ahc->platform_data->host);
}

static void
ahc_linux_release_sim_queue(u_long arg)
{
	struct ahc_softc *ahc;
	u_long s;
	int    unblock_reqs;

	ahc = (struct ahc_softc *)arg;
	unblock_reqs = 0;
	ahc_lock(ahc, &s);
	if (ahc->platform_data->qfrozen > 0)
		ahc->platform_data->qfrozen--;
	if (ahc->platform_data->qfrozen == 0) {
		unblock_reqs = 1;
	}
	ahc_unlock(ahc, &s);
	/*
	 * There is still a race here.  The mid-layer
	 * should keep its own freeze count and use
	 * a bottom half handler to run the queues
	 * so we can unblock with our own lock held.
	 */
	if (unblock_reqs) {
		scsi_unblock_requests(ahc->platform_data->host);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		tasklet_schedule(&ahc->platform_data->runq_tasklet);
#else
		ahc_runq_tasklet((unsigned long)ahc);
#endif
	}
}
#endif /* 0 */

static void
ahc_linux_dev_timed_unfreeze(u_long arg)
{
	struct ahc_linux_device *dev;
	struct ahc_softc *ahc;
	u_long s;

	dev = (struct ahc_linux_device *)arg;
	ahc = dev->target->ahc;
	ahc_lock(ahc, &s);
	dev->flags &= ~AHC_DEV_TIMER_ACTIVE;
	if (dev->qfrozen > 0)
		dev->qfrozen--;
	if (dev->qfrozen == 0
	 && (dev->flags & AHC_DEV_ON_RUN_LIST) == 0)
		ahc_linux_run_device_queue(ahc, dev);
	ahc_unlock(ahc, &s);
}

static int
ahc_linux_queue_recovery_cmd(Scsi_Cmnd *cmd, scb_flag flag)
{
	struct ahc_softc *ahc;
	struct ahc_cmd *acmd;
	struct ahc_cmd *list_acmd;
	struct ahc_linux_device *dev;
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
	ahc = *(struct ahc_softc **)cmd->host->hostdata;
	acmd = (struct ahc_cmd *)cmd;

	printf("%s:%d:%d:%d: Attempting to queue a%s message\n",
	       ahc_name(ahc), cmd->channel, cmd->target, cmd->lun,
	       flag == SCB_ABORT ? "n ABORT" : " TARGET RESET");

	/*
	 * It is a bug that the upper layer takes
	 * this lock just prior to calling us.
	 */
	spin_unlock_irq(&io_request_lock);

	ahc_lock(ahc, &s);

	/*
	 * First determine if we currently own this command.
	 * Start by searching the device queue.  If not found
	 * there, check the pending_scb list.  If not found
	 * at all, and the system wanted us to just abort the
	 * command return success.
	 */
	dev = ahc_linux_get_device(ahc, cmd->channel, cmd->target,
				   cmd->lun, /*alloc*/FALSE);

	if (dev == NULL) {
		/*
		 * No target device for this command exists,
		 * so we must not still own the command.
		 */
		printf("%s:%d:%d:%d: Is not an active device\n",
		       ahc_name(ahc), cmd->channel, cmd->target, cmd->lun);
		retval = SUCCESS;
		goto no_cmd;
	}

	TAILQ_FOREACH(list_acmd, &dev->busyq, acmd_links.tqe) {
		if (list_acmd == acmd)
			break;
	}

	if (list_acmd != NULL) {
		printf("%s:%d:%d:%d: Command found on device queue\n",
		       ahc_name(ahc), cmd->channel, cmd->target, cmd->lun);
		if (flag == SCB_ABORT) {
			TAILQ_REMOVE(&dev->busyq, list_acmd, acmd_links.tqe);
			cmd->result = DID_ABORT << 16;
			ahc_linux_queue_cmd_complete(ahc, cmd);
			retval = SUCCESS;
			goto done;
		}
	}

	if ((dev->flags & (AHC_DEV_Q_BASIC|AHC_DEV_Q_TAGGED)) == 0
	 && ahc_search_untagged_queues(ahc, cmd, cmd->target,
				       cmd->channel + 'A', cmd->lun,
				       CAM_REQ_ABORTED, SEARCH_COMPLETE) != 0) {
		printf("%s:%d:%d:%d: Command found on untagged queue\n",
		       ahc_name(ahc), cmd->channel, cmd->target, cmd->lun);
		retval = SUCCESS;
		goto done;
	}

	/*
	 * See if we can find a matching cmd in the pending list.
	 */
	LIST_FOREACH(pending_scb, &ahc->pending_scbs, pending_links) {
		if (pending_scb->io_ctx == cmd)
			break;
	}

	if (pending_scb == NULL && flag == SCB_DEVICE_RESET) {

		/* Any SCB for this device will do for a target reset */
		LIST_FOREACH(pending_scb, &ahc->pending_scbs, pending_links) {
		  	if (ahc_match_scb(ahc, pending_scb, cmd->target,
					  cmd->channel + 'A', CAM_LUN_WILDCARD,
					  SCB_LIST_NULL, ROLE_INITIATOR) == 0)
				break;
		}
	}

	if (pending_scb == NULL) {
		printf("%s:%d:%d:%d: Command not found\n",
		       ahc_name(ahc), cmd->channel, cmd->target, cmd->lun);
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
	 * behind our back and that no selections have occurred
	 * that have not been serviced.  Also make sure that we
	 * didn't "just" miss an interrupt that would
	 * affect this cmd.
	 */
	ahc->flags |= AHC_ALL_INTERRUPTS;
	do {
		if (paused)
			ahc_unpause(ahc);
		ahc_intr(ahc);
		ahc_pause(ahc);
		paused = TRUE;
		ahc_outb(ahc, SCSISEQ, ahc_inb(ahc, SCSISEQ) & ~ENSELO);
		ahc_clear_critical_section(ahc);
	} while ((ahc_inb(ahc, INTSTAT) & INT_PEND) != 0
	      || (ahc_inb(ahc, SSTAT0) & (SELDO|SELINGO)));
	ahc->flags &= ~AHC_ALL_INTERRUPTS;

	ahc_dump_card_state(ahc);

	if ((pending_scb->flags & SCB_ACTIVE) == 0) {
		printf("%s:%d:%d:%d: Command already completed\n",
		       ahc_name(ahc), cmd->channel, cmd->target, cmd->lun);
		goto no_cmd;
	}

	disconnected = TRUE;
	if (flag == SCB_ABORT) {
		if (ahc_search_qinfifo(ahc, cmd->target, cmd->channel + 'A',
				       cmd->lun, pending_scb->hscb->tag,
				       ROLE_INITIATOR, CAM_REQ_ABORTED,
				       SEARCH_COMPLETE) > 0) {
			printf("%s:%d:%d:%d: Cmd aborted from QINFIFO\n",
			       ahc_name(ahc), cmd->channel, cmd->target,
					cmd->lun);
			retval = SUCCESS;
			goto done;
		}
	} else if (ahc_search_qinfifo(ahc, cmd->target, cmd->channel + 'A',
				      cmd->lun, pending_scb->hscb->tag,
				      ROLE_INITIATOR, /*status*/0,
				      SEARCH_COUNT) > 0) {
		disconnected = FALSE;
	}

	if (disconnected && (ahc_inb(ahc, SEQ_FLAGS) & IDENTIFY_SEEN) != 0) {
		struct scb *bus_scb;

		bus_scb = ahc_lookup_scb(ahc, ahc_inb(ahc, SCB_TAG));
		if (bus_scb == pending_scb)
			disconnected = FALSE;
		else if (flag != SCB_ABORT
		      && ahc_inb(ahc, SAVED_SCSIID) == pending_scb->hscb->scsiid
		      && ahc_inb(ahc, SAVED_LUN) == pending_scb->hscb->lun)
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
	last_phase = ahc_inb(ahc, LASTPHASE);
	saved_scbptr = ahc_inb(ahc, SCBPTR);
	active_scb_index = ahc_inb(ahc, SCB_TAG);
	if (last_phase != P_BUSFREE
	 && (pending_scb->hscb->tag == active_scb_index
	  || (flag == SCB_DEVICE_RESET
	   && SCSIID_TARGET(ahc, ahc_inb(ahc, SAVED_SCSIID)) == cmd->target))) {

		/*
		 * We're active on the bus, so assert ATN
		 * and hope that the target responds.
		 */
		pending_scb = ahc_lookup_scb(ahc, active_scb_index);
		pending_scb->flags |= SCB_RECOVERY_SCB|flag;
		ahc_outb(ahc, MSG_OUT, HOST_MSG);
		ahc_outb(ahc, SCSISIGO, last_phase|ATNO);
		printf("%s:%d:%d:%d: Device is active, asserting ATN\n",
		       ahc_name(ahc), cmd->channel, cmd->target, cmd->lun);
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
		 * Remove any cached copy of this SCB in the
		 * disconnected list in preparation for the
		 * queuing of our abort SCB.  We use the
		 * same element in the SCB, SCB_NEXT, for
		 * both the qinfifo and the disconnected list.
		 */
		ahc_search_disc_list(ahc, cmd->target, cmd->channel + 'A',
				     cmd->lun, pending_scb->hscb->tag,
				     /*stop_on_first*/TRUE,
				     /*remove*/TRUE,
				     /*save_state*/FALSE);

		/*
		 * In the non-paging case, the sequencer will
		 * never re-reference the in-core SCB.
		 * To make sure we are notified during
		 * reslection, set the MK_MESSAGE flag in
		 * the card's copy of the SCB.
		 */
		if ((ahc->flags & AHC_PAGESCBS) == 0) {
			ahc_outb(ahc, SCBPTR, pending_scb->hscb->tag);
			ahc_outb(ahc, SCB_CONTROL,
				 ahc_inb(ahc, SCB_CONTROL)|MK_MESSAGE);
		}

		/*
		 * Clear out any entries in the QINFIFO first
		 * so we are the next SCB for this target
		 * to run.
		 */
		ahc_search_qinfifo(ahc, cmd->target, cmd->channel + 'A',
				   cmd->lun, SCB_LIST_NULL, ROLE_INITIATOR,
				   CAM_REQUEUE_REQ, SEARCH_COMPLETE);
		ahc_print_path(ahc, pending_scb);
		printf("Queuing a recovery SCB\n");
		ahc_qinfifo_requeue_tail(ahc, pending_scb);
		ahc_outb(ahc, SCBPTR, saved_scbptr);
		printf("%s:%d:%d:%d: Device is disconnected, re-queuing SCB\n",
		       ahc_name(ahc), cmd->channel, cmd->target, cmd->lun);
		wait = TRUE;
	} else {
		printf("%s:%d:%d:%d: Unable to deliver message\n",
		       ahc_name(ahc), cmd->channel, cmd->target, cmd->lun);
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
		ahc_unpause(ahc);
	if (wait) {
	  // JWS - XEN	- err...  
	  printf("JWS - aic7xxx: recovery-wait: doh\n");
	  retval=FAILED;
	  /*
		struct timer_list timer;
		int ret;

		ahc_unlock(ahc, &s);
		init_timer(&timer);
		timer.data = (u_long)&ahc->platform_data->eh_sem;
		timer.expires = jiffies + (5 * HZ);
		timer.function = ahc_linux_sem_timeout;
		add_timer(&timer);
		printf("Recovery code sleeping\n");
		down(&ahc->platform_data->eh_sem);
		printf("Recovery code awake\n");
        	ret = del_timer(&timer);
		if (ret == 0) {
			printf("Timer Expired\n");
			retval = FAILED;
		}
		ahc_lock(ahc, &s);
	  */
	}
	acmd = TAILQ_FIRST(&ahc->platform_data->completeq);
	TAILQ_INIT(&ahc->platform_data->completeq);
	ahc_unlock(ahc, &s);
	if (acmd != NULL)
		ahc_linux_run_complete_queue(ahc, acmd);
	ahc_runq_tasklet((unsigned long)ahc);
	spin_lock_irq(&io_request_lock);
	return (retval);
}

/*
 * Abort the current SCSI command(s).
 */
int
ahc_linux_abort(Scsi_Cmnd *cmd)
{
	int error;

	error = ahc_linux_queue_recovery_cmd(cmd, SCB_ABORT);
	if (error != 0)
		printf("aic7xxx_abort returns 0x%x\n", error);
	return (error);
}

/*
 * Attempt to send a target reset message to the device that timed out.
 */
int
ahc_linux_dev_reset(Scsi_Cmnd *cmd)
{
	int error;

	error = ahc_linux_queue_recovery_cmd(cmd, SCB_DEVICE_RESET);
	if (error != 0)
		printf("aic7xxx_dev_reset returns 0x%x\n", error);
	return (error);
}

/*
 * Reset the SCSI bus.
 */
int
ahc_linux_bus_reset(Scsi_Cmnd *cmd)
{
	struct ahc_softc *ahc;
	struct ahc_cmd *acmd;
	u_long s;
	int    found;

	/*
	 * It is a bug that the upper layer takes
	 * this lock just prior to calling us.
	 */
	spin_unlock_irq(&io_request_lock);

	ahc = *(struct ahc_softc **)cmd->host->hostdata;
	ahc_lock(ahc, &s);
	found = ahc_reset_channel(ahc, cmd->channel + 'A',
				  /*initiate reset*/TRUE);
	acmd = TAILQ_FIRST(&ahc->platform_data->completeq);
	TAILQ_INIT(&ahc->platform_data->completeq);
	ahc_unlock(ahc, &s);
	if (bootverbose)
		printf("%s: SCSI bus reset delivered. "
		       "%d SCBs aborted.\n", ahc_name(ahc), found);

	if (acmd != NULL)
		ahc_linux_run_complete_queue(ahc, acmd);

	spin_lock_irq(&io_request_lock);
	return SUCCESS;
}

/*
 * Return the disk geometry for the given SCSI device.
 */
int
ahc_linux_biosparam(Disk *disk, kdev_t dev, int geom[])
{
	int	heads;
	int	sectors;
	int	cylinders;
	//int	ret;
	int	extended;
	struct	ahc_softc *ahc;
	//struct	buffer_head *bh;

	ahc = *((struct ahc_softc **)disk->device->host->hostdata);
#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,17)
	bh = bread(MKDEV(MAJOR(dev), MINOR(dev) & ~0xf), 0, block_size(dev));
#else
	bh = bread(MKDEV(MAJOR(dev), MINOR(dev) & ~0xf), 0, 1024);
#endif

	if (bh) {
		ret = scsi_partsize(bh, disk->capacity,
				    &geom[2], &geom[0], &geom[1]);
		brelse(bh);
		if (ret != -1)
			return (ret);
	}
#endif
	heads = 64;
	sectors = 32;
	cylinders = disk->capacity / (heads * sectors);

	if (aic7xxx_extended != 0)
		extended = 1;
	else if (disk->device->channel == 0)
		extended = (ahc->flags & AHC_EXTENDED_TRANS_A) != 0;
	else
		extended = (ahc->flags & AHC_EXTENDED_TRANS_B) != 0;
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
ahc_linux_release(struct Scsi_Host * host)
{
	struct ahc_softc *ahc;
	u_long l;

	ahc_list_lock(&l);
	if (host != NULL) {

		/*
		 * We should be able to just perform
		 * the free directly, but check our
		 * list for extra sanity.
		 */
		ahc = ahc_find_softc(*(struct ahc_softc **)host->hostdata);
		if (ahc != NULL) {
			u_long s;

			ahc_lock(ahc, &s);
			ahc_intr_enable(ahc, FALSE);
			ahc_unlock(ahc, &s);
			ahc_free(ahc);
		}
	}
	ahc_list_unlock(&l);
	return (0);
}

void
ahc_platform_dump_card_state(struct ahc_softc *ahc)
{
	struct ahc_linux_device *dev;
	int channel;
	int maxchannel;
	int target;
	int maxtarget;
	int lun;
	int i;

	maxchannel = (ahc->features & AHC_TWIN) ? 1 : 0;
	maxtarget = (ahc->features & AHC_WIDE) ? 15 : 7;
	for (channel = 0; channel <= maxchannel; channel++) {

		for (target = 0; target <=maxtarget; target++) {

			for (lun = 0; lun < AHC_NUM_LUNS; lun++) {
				struct ahc_cmd *acmd;

				dev = ahc_linux_get_device(ahc, channel, target,
							   lun, /*alloc*/FALSE);
				if (dev == NULL)
					continue;

				printf("DevQ(%d:%d:%d): ",
				       channel, target, lun);
				i = 0;
				TAILQ_FOREACH(acmd, &dev->busyq,
					      acmd_links.tqe) {
					if (i++ > AHC_SCB_MAX)
						break;
				}
				printf("%d waiting\n", i);
			}
		}
	}
}


#if defined(MODULE) || LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
static Scsi_Host_Template driver_template = AIC7XXX;
Scsi_Host_Template *aic7xxx_driver_template = &driver_template;
#include "../scsi_module.c.inc"
#endif

