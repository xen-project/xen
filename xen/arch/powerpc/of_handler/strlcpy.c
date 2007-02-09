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
 * Copyright IBM Corp. 2005, 2007
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 *          Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <xen/string.h>

size_t
strlcpy(char *dest, const char *src, size_t n)
{
	size_t ret;
    char *dp;

    /* cases to consider:
     *   dest is NULL, s is NULL;
     *   src is empty (0);
     *   src is not empty, less than n;
     *   src is not empty, equal to n;
     *   src is not empty, greater than n;
     */

    if (n <= 0) {
        return 0;
    }
  
    dp = dest;

    do {
        *dp++ = *src;
        --n;
        ++src;
    } while ((*src != '\0') && (n > 1));

    ret = n;
  
    /* clear remainder of buffer (if any);  ANSI semantics */
    while (n > 0) {
        *dp++ = '\0';
        --n;
    }
    return ret;
}
