/*
 * MCA implementation for AMD Family10 CPUs
 * Copyright (c) 2007 Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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


/* K8 common MCA documentation published at
 *
 * AMD64 Architecture Programmer's Manual Volume 2:
 * System Programming
 * Publication # 24593 Revision: 3.12
 * Issue Date: September 2006
 */

/* Family10 MCA documentation published at
 *
 * BIOS and Kernel Developer's Guide
 * For AMD Family 10h Processors
 * Publication # 31116 Revision: 1.08
 * Isse Date: June 10, 2007
 */


#include <xen/init.h>
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/config.h>
#include <xen/smp.h>

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/msr.h>

#include "mce.h"
#include "mce_quirks.h"
#include "x86_mca.h"


static struct mcinfo_extended *
amd_f10_handler(struct mc_info *mi, uint16_t bank, uint64_t status)
{
	struct mcinfo_extended *mc_ext;

	/* Family 0x10 introduced additional MSR that belong to the
	 * northbridge bank (4). */
	if (mi == NULL || bank != 4)
		return NULL;

	if (!(status & MCi_STATUS_VAL))
		return NULL;

	if (!(status & MCi_STATUS_MISCV))
		return NULL;

	mc_ext = x86_mcinfo_reserve(mi, sizeof(struct mcinfo_extended));
	if (!mc_ext)
	{
		mi->flags |= MCINFO_FLAGS_UNCOMPLETE;
		return NULL;
	}

	memset(mc_ext, 0, sizeof(*mc_ext));
	mc_ext->common.type = MC_TYPE_EXTENDED;
	mc_ext->common.size = sizeof(*mc_ext);
	mc_ext->mc_msrs = 3;

	mc_ext->mc_msr[0].reg = MSR_F10_MC4_MISC1;
	mc_ext->mc_msr[1].reg = MSR_F10_MC4_MISC2;
	mc_ext->mc_msr[2].reg = MSR_F10_MC4_MISC3;

	mc_ext->mc_msr[0].value = mca_rdmsr(MSR_F10_MC4_MISC1);
	mc_ext->mc_msr[1].value = mca_rdmsr(MSR_F10_MC4_MISC2);
	mc_ext->mc_msr[2].value = mca_rdmsr(MSR_F10_MC4_MISC3);

	return mc_ext;
}

/* AMD Family10 machine check */
enum mcheck_type amd_f10_mcheck_init(struct cpuinfo_x86 *c)
{ 
	enum mcequirk_amd_flags quirkflag = mcequirk_lookup_amd_quirkdata(c);

	if (amd_k8_mcheck_init(c) == mcheck_none)
		return mcheck_none;

	if (quirkflag == MCEQUIRK_F10_GART)
		mcequirk_amd_apply(quirkflag);

	x86_mce_callback_register(amd_f10_handler);

	return mcheck_amd_famXX;
}
