/* * MCA quirks
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _MCE_QUIRK_H
#define _MCE_QUIRK_H

#include <xen/types.h>

struct mce_quirkdata {
	int32_t cpu_family;
	int16_t cpu_model;
	int16_t cpu_stepping;
	uint32_t quirk;
};

/* use a binary flag if multiple quirks apply
 * to one CPU family/model
 */

enum mcequirk_amd_flags {
	MCEQUIRK_K8_GART = 2,
	MCEQUIRK_F10_GART
};

enum mcequirk_intel_flags {
	MCEQUIRK_DUMMY = 0x1, /* nothing known yet */
};

enum mcequirk_amd_flags
mcequirk_lookup_amd_quirkdata(struct cpuinfo_x86 *c);

int mcequirk_amd_apply(enum mcequirk_amd_flags flags);

enum mcequirk_intel_flags
mcequirk_lookup_intel_quirkdata(struct cpuinfo_x86 *c);

int mcequirk_intel_apply(enum mcequirk_intel_flags flags);

#endif /* _MCE_QUIRK_H */
