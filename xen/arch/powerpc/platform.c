/*
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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright IBM Corp. 2007
 *
 * Authors: Ryan Harper <ryanh@us.ibm.com>
 *          Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <asm/page.h>
#include <asm/platform.h>

#define IO_RANGE_START (2UL << 30)
#define IO_RANGE_END   (4UL << 30)
#define IO_SIZE        (IO_RANGE_END - IO_RANGE_START)

unsigned long platform_iohole_base(void)
{
    return IO_RANGE_START;
}

unsigned long platform_iohole_size(void)
{
    return IO_SIZE;
}

int platform_io_mfn(unsigned long mfn)
{
    unsigned long maddr = mfn << PAGE_SHIFT;
    return maddr > IO_RANGE_START && maddr < IO_RANGE_END;
}
