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
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/delay.h>
#include <xen/time.h>
#include <asm/processor.h>

void udelay(unsigned long usecs)
{
    ulong ticks = usecs * ticks_per_usec;
    ulong s;
    ulong e;

    s = get_timebase();
    do {
        asm volatile("or 1,1,1"); /* also puts the thread to low priority */
        e = get_timebase();
    } while ((e-s) < ticks);
}
