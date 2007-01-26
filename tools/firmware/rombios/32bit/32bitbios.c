/*
 *  32bitbios - jumptable for those function reachable from 16bit area
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */
#include "rombios_compat.h"
#include "jumptable.h"
#include "32bitprotos.h"

/* same prototypes as in the 16bit BIOS */
Bit32u multiply(Bit32u a, Bit32u b)
{
	return a*b;
}

Bit32u add(Bit32u a, Bit32u b)
{
	return a+b;
}

static Bit32u stat_a = 0x1;
Bit32u set_static(Bit32u a)
{
	Bit32u _a = stat_a;
	stat_a = a;
	return _a;
}


/*
   the jumptable that will be copied into the rombios in the 0xf000 segment
   for every function that is to be called from the lower BIOS, make an entry
   here.
 */
#define TABLE_ENTRY(idx, func) [idx] = (uint32_t)func
uint32_t jumptable[IDX_LAST+1] __attribute__((section (JUMPTABLE_SECTION_NAME))) =
{
	TABLE_ENTRY(IDX_MULTIPLY   , multiply),
	TABLE_ENTRY(IDX_ADD        , add),
	TABLE_ENTRY(IDX_SET_STATIC , set_static),


	TABLE_ENTRY(IDX_LAST       , 0)     /* keep last */
};
