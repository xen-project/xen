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

#include <xen/string.h>

void *
memset(void *s, int c, size_t n)
{
    uint8_t *ss = (uint8_t *)s;

    if (n == 0) {
        return s;
    }

    /* yes, I pulled the 2 out of this air */
    if (n >= (2 * sizeof (ulong))) {
        ulong val = 0;
        ulong i;

        /* construct val assignment from c */
        if (c != 0) {
            for (i = 0; i < sizeof (ulong); i++) {
                val = (val << 8) | c;
            }
        }

        /* do by character until aligned */
        while (((ulong)ss & (sizeof (ulong) - 1)) > 0) {
            *ss = c;
            ++ss;
            --n;
        }

        /* now do the aligned stores */
        while (n >= sizeof (ulong)) {
            *(ulong *)ss = val;
            ss += sizeof (ulong);
            n -= sizeof (ulong);
        }
    }
    /* do that last unaligned bit */
    while (n > 0) {
        *ss = c;
        ++ss;
        --n;

    }          

    return s;
}
