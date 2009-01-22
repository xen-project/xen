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

/*
   the jumptable that will be copied into the rombios in the 0xf000 segment
   for every function that is to be called from the lower BIOS, make an entry
   here.
 */
uint32_t jumptable[] __attribute__((section (".biosjumptable"))) =
{
#define X(idx, ret, fn, args...) [idx] = (uint32_t)fn,
#include "32bitprotos.h"
#undef X
};
