/*
 * MCA quirks for AMD CPUs
 * Copyright (c) 2009 Advanced Micro Devices, Inc.
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

#include <asm-x86/msr.h>
#include <asm-x86/processor.h>

#include "mce_quirks.h"

#define ANY -1

static const struct mce_quirkdata mce_amd_quirks[] = {
	{ 0x6 /* cpu family */, ANY /* all models */, ANY /* all steppings */,
	  MCEQUIRK_K7_BANK0 },
	{ 0xf /* cpu family */, ANY /* all models */, ANY /* all steppings */,
	  MCEQUIRK_K8_GART },
	{ 0x10 /* cpu family */, ANY /* all models */, ANY /* all steppings */,
	  MCEQUIRK_F10_GART },
};

enum mcequirk_amd_flags
mcequirk_lookup_amd_quirkdata(struct cpuinfo_x86 *c)
{
	int i;

	BUG_ON(c->x86_vendor != X86_VENDOR_AMD);

	for (i = 0; i < ARRAY_SIZE(mce_amd_quirks); i++) {
		if (c->x86 != mce_amd_quirks[i].cpu_family)
			continue;
		if ( (mce_amd_quirks[i].cpu_model != ANY) &&
		     (mce_amd_quirks[i].cpu_model != c->x86_model) )
			continue;
		if ( (mce_amd_quirks[i].cpu_stepping != ANY) &&
		     (mce_amd_quirks[i].cpu_stepping != c->x86_mask) )
			continue;
		return mce_amd_quirks[i].quirk;
	}
	return 0;
}

int mcequirk_amd_apply(enum mcequirk_amd_flags flags)
{
	u64 val;

	switch (flags) {
	case MCEQUIRK_K7_BANK0:
		return 1; /* first bank */

	case MCEQUIRK_K8_GART:
		/*
		 * Enable error reporting for all errors except for GART
		 * TBL walk error reporting, which trips off incorrectly
		 * with AGP GART & 3ware & Cerberus.
		 */
		wrmsrl(MSR_IA32_MCx_CTL(4), ~(1ULL << 10));
		wrmsrl(MSR_IA32_MCx_STATUS(4), 0ULL);
		break;
	case MCEQUIRK_F10_GART:
		if (rdmsr_safe(MSR_AMD64_MCx_MASK(4), val) == 0)
			wrmsr_safe(MSR_AMD64_MCx_MASK(4), val | (1 << 10));
		break;
	}

	return 0;
}
