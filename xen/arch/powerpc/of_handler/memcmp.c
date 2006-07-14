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

int
memcmp(const void *v1, const void *v2, size_t n)
{
    const char *s1 = (const char *)v1;
    const char *s2 = (const char *)v2;

    while (n > 0) {
        if (*s1 != *s2) {
            return (*s1 - *s2);
        }
        /* advance pointers to next character */
        ++s1;
        ++s2;
        --n;
    }
    return 0;
}
