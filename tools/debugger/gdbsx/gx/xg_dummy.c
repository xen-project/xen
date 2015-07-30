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
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>

#include "gx.h"
#include "../xg/xg_public.h"

int xgtrc_on = 1;

/* This file is NOT part of gdbsx binary, but a dummy so gdbsx bin can be built
 * and used to learn/test "gdb <-> gdbserver" protocol */

void
xgtrc(const char *fn, const char *fmt, ...)
{
    char buf[2048];
    va_list     args;

    fprintf(stderr, "%s:", fn);
    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    fprintf(stderr, "%s", buf);
    fflush (stderr);
}   
    
void
xgprt(const char *fn, const char *fmt, ...)
{   
    char buf[2048];
    va_list     args;

    fprintf(stderr, "%s:", fn);
    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    fprintf (stderr, "%s", buf);
    fflush (stderr);
}

int
xg_init()
{
    return 0;
}

void
xg_deinit()
{
    /* reset debugging info in guest */
    /* unpause the guest */
}

int
xg_attach(domid_t domid)
{
    return 2;
}

int
xg_step(vcpuid_t which_vcpu, int guest_bitness)
{
    return 0;
}

int
xg_resume(int guest_bitness)
{
    return 0;
}

int
xg_regs_read(regstype_t which_regs, vcpuid_t which_vcpu,
             struct xg_gdb_regs *regsp, int guest_bitness)
{
    return 0;
}

int
xg_regs_write(regstype_t which_regs, vcpuid_t which_vcpu,
              struct xg_gdb_regs *regsp, int guest_bitness)
{
    return 0;
}

int
xg_read_mem(uint64_t guestva, char *tobuf, int len)
{
    return 0;
}

int
xg_write_mem(uint64_t guestva, char *frombuf, int len)
{
    return 0;
}

int
xg_wait_domain(vcpuid_t *vcpu_p, int guest_bitness)
{
    return 0;
}

