/*
 * Adaptec AIC79xx device driver host template for Linux.
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
 * $Id: //depot/aic7xxx/linux/drivers/scsi/aic7xxx/aic79xx_host.h#6 $
 */

#ifndef _AIC79XX_LINUX_HOST_H_
#define _AIC79XX_LINUX_HOST_H_

int		 ahd_linux_proc_info(char *, char **, off_t, int, int, int);
int		 ahd_linux_queue(Scsi_Cmnd *, void (*)(Scsi_Cmnd *));
int		 ahd_linux_detect(Scsi_Host_Template *);
int		 ahd_linux_release(struct Scsi_Host *);
const char	*ahd_linux_info(struct Scsi_Host *);
int		 ahd_linux_biosparam(Disk *, kdev_t, int[]);
int		 ahd_linux_bus_reset(Scsi_Cmnd *);
int		 ahd_linux_dev_reset(Scsi_Cmnd *);
int		 ahd_linux_abort(Scsi_Cmnd *);

#if defined(__i386__)
#  define AIC79XX_BIOSPARAM ahd_linux_biosparam
#else
#  define AIC79XX_BIOSPARAM NULL
#endif

/*
 * Scsi_Host_Template (see hosts.h) for AIC-79xx - some fields
 * to do with card config are filled in after the card is detected.
 */
#define AIC79XX	{						\
	next: NULL,						\
	module: NULL,						\
	proc_dir: NULL,						\
	proc_info: ahd_linux_proc_info,				\
	name: NULL,						\
	detect: ahd_linux_detect,				\
	release: ahd_linux_release,				\
	info: ahd_linux_info,					\
	command: NULL,						\
	queuecommand: ahd_linux_queue,				\
	eh_strategy_handler: NULL,				\
	eh_abort_handler: ahd_linux_abort,			\
	eh_device_reset_handler: ahd_linux_dev_reset,		\
	eh_bus_reset_handler: ahd_linux_bus_reset,		\
	eh_host_reset_handler: NULL,				\
	abort: NULL,						\
	reset: NULL,						\
	slave_attach: NULL,					\
	bios_param: AIC79XX_BIOSPARAM,				\
	can_queue: AHD_MAX_QUEUE,/* max simultaneous cmds     */\
	this_id: -1,		 /* scsi id of host adapter   */\
	sg_tablesize: AHD_NSEG,	 /* max scatter-gather cmds   */\
	cmd_per_lun: 2,		 /* cmds per lun	      */\
	present: 0,		 /* number of 7xxx's present  */\
	unchecked_isa_dma: 0,	 /* no memory DMA restrictions*/\
	use_clustering: ENABLE_CLUSTERING,			\
	use_new_eh_code: 1					\
}

#endif /* _AIC79XX_LINUX_HOST_H_ */
