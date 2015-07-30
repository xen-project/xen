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
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

typedef uint16_t domid_t;
typedef unsigned char uchar;

#include "../xg/xg_public.h"

int gx_remote_open (char *commstr);
void gx_remote_close(void);
int gx_getpkt (char *buf);
void gx_write_ok(char *buf);
void gx_write_err(char *buf);
void gx_convert_int_to_ascii (char *from, char *to, int n);
void gx_convert_ascii_to_int (char *from, char *to, int n);
int gx_putpkt (char *buf);
void gx_decode_m_packet(char *, uint64_t *, int *);
char *gx_decode_M_packet(char *, uint64_t *, int *);
void gx_decode_zZ_packet(char *, uint64_t *);
void gx_reply_ok(char *);
void gx_reply_error(char *);
int gx_fromhex(int);
int gx_tohex(int);
int gx_local_cmd(domid_t domid, vcpuid_t vcpuid);
void gxprt(const char *fmt, ...);
