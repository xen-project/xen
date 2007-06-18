/*
 *  Xen domain0 platform firmware fixups for sn2
 *  Copyright (C) 2007 Silicon Graphics Inc.
 *       Jes Sorensen <jes@sgi.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/config.h>
#include <xen/acpi.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/nodemask.h>

#include <asm/dom_fw.h>
#include <asm/dom_fw_common.h>
#include <asm/dom_fw_dom0.h>
#include <asm/dom_fw_utils.h>

#include <asm/sn/arch.h>
#include <asm/sn/addrs.h>
#include <asm/sn/shub_mmr.h>

#define SWAP_NASID(n, x)       ((x & ~NASID_MASK) | NASID_SPACE(n))

int __init
sn2_dom_fw_init(domain_t *d,
		struct xen_ia64_boot_param *bp,
		struct fw_tables *tables)
{
	int node;
	short nasid;
	unsigned long shubid, shubpicam, shubpiowrite;

	printk("SN2 mapping specific registers to dom0\n");

	assign_domain_mach_page(d, LOCAL_MMR_OFFSET | SH_RTC, PAGE_SIZE,
				ASSIGN_nocache);

	if (is_shub1()) {
		/* 0x110060000 */
		shubid = SH1_GLOBAL_MMR_OFFSET + (SH1_SHUB_ID & PAGE_MASK);
		/* 0x120050000 */
		shubpicam = SH1_GLOBAL_MMR_OFFSET +
			(SH1_PI_CAM_CONTROL & PAGE_MASK);
		/* 0x120070000 */
		shubpiowrite = SH1_GLOBAL_MMR_OFFSET +
			(SH1_PIO_WRITE_STATUS_0 & PAGE_MASK);

		for_each_online_node(node) {
			nasid = cnodeid_to_nasid(node);
			shubid = SWAP_NASID(nasid, shubid);
			shubpicam = SWAP_NASID(nasid, shubpicam);
			shubpiowrite = SWAP_NASID(nasid, shubpiowrite);

			assign_domain_mach_page(d, shubid, PAGE_SIZE,
						ASSIGN_nocache);
			assign_domain_mach_page(d, shubpicam, PAGE_SIZE,
						ASSIGN_nocache);
			assign_domain_mach_page(d, shubpiowrite, PAGE_SIZE,
						ASSIGN_nocache);
		}

		/* map leds */
		assign_domain_mach_page(d, LOCAL_MMR_OFFSET |
					SH1_REAL_JUNK_BUS_LED0,
					PAGE_SIZE, ASSIGN_nocache);
		assign_domain_mach_page(d, LOCAL_MMR_OFFSET |
					SH1_REAL_JUNK_BUS_LED1,
					PAGE_SIZE, ASSIGN_nocache);
		assign_domain_mach_page(d, LOCAL_MMR_OFFSET |
					SH1_REAL_JUNK_BUS_LED2,
					PAGE_SIZE, ASSIGN_nocache);
		assign_domain_mach_page(d, LOCAL_MMR_OFFSET |
					SH1_REAL_JUNK_BUS_LED3,
					PAGE_SIZE, ASSIGN_nocache);
	} else
		panic("Unable to build EFI entry for SHUB 2 MMR\n");

	return 0;
}
