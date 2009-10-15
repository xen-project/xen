/*
 * Copyright (C) 2009, Mukesh Rathor, Oracle Corp.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#include "gx.h"


void
gxprt(const char *fmt, ...)
{
    char buf[2048];
    va_list args;

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    fprintf(stderr, "%s", buf);
    fflush(stderr);
}

int
gx_fromhex(int a)
{
    if (a >= '0' && a <= '9')
        return a - '0';
    else if (a >= 'a' && a <= 'f')
        return a - 'a' + 10;
    else
        gxprt("Reply contains invalid hex digit");
    return 0;
}

int
gx_tohex(int nib)
{
    if (nib < 10)
        return '0' + nib;
    else
        return 'a' + nib - 10;
}


void
gx_convert_int_to_ascii(char *from, char *to, int n)
{
    int nib;
    int ch;
    while (n--) {
        ch = *from++;
        nib = ((ch & 0xf0) >> 4) & 0x0f;
        *to++ = gx_tohex(nib);
        nib = ch & 0x0f;
        *to++ = gx_tohex(nib);
    }
    *to = 0;
}

/* input: "70676433206431" output: "pgd3 d1" n == 7 */
void
gx_convert_ascii_to_int(char *from, char *to, int n)
{
    int nib1, nib2;
    while (n--) {
        nib1 = gx_fromhex(*from++);
        nib2 = gx_fromhex(*from++);
        *to++ = (((nib1 & 0x0f) << 4) & 0xf0) | (nib2 & 0x0f);
    }
    *to = 0;
}

void
gx_decode_zZ_packet(char *from, uint64_t *mem_addr_ptr)
{
    int i = 0;
    char ch;
    *mem_addr_ptr = 0;

    while ((ch=from[i++]) != ',') {
        *mem_addr_ptr = *mem_addr_ptr << 4;
        *mem_addr_ptr |= gx_fromhex(ch) & 0x0f;
    }
}

/* Eg: mc0267d3a,1\0 : from points to char after 'm' */
void
gx_decode_m_packet(char *from, uint64_t *mem_addr_ptr, int *len_ptr)
{
    int i = 0, j = 0;
    char ch;
    *mem_addr_ptr = *len_ptr = 0;

    while ((ch=from[i++]) != ',') {
        *mem_addr_ptr = *mem_addr_ptr << 4;
        *mem_addr_ptr |= gx_fromhex(ch) & 0x0f;
    }
    for (j = 0; j < 4; j++) {
        if ((ch=from[i++]) == 0)
            break;
        *len_ptr = *len_ptr << 4;
        *len_ptr |= gx_fromhex(ch) & 0x0f;
    }
}

/*
 * Decode M pkt as in: Mc0267d3a,1:cc\0 where c0267d3a is the guest addr
 * from points to char after 'M'
 * Returns: address of byte after ":", ie, addr of cc in buf
 */
char *
gx_decode_M_packet(char *from, uint64_t *mem_addr_ptr, int *len_ptr)
{
    int i = 0;
    char ch;

    *mem_addr_ptr = *len_ptr = 0;

    while ((ch=from[i++]) != ',') {
        *mem_addr_ptr = *mem_addr_ptr << 4;
        *mem_addr_ptr |= gx_fromhex(ch) & 0x0f;
    }
    while ((ch = from[i++]) != ':') {
        *len_ptr = *len_ptr << 4;
        *len_ptr |= gx_fromhex(ch) & 0x0f;
    }
    return(&from[i]);
}

