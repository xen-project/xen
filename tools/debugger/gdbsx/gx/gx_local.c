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


/* This file to impelement functions that run interactively and don't 
 * involve remote gdb. Eg, print vcpu context and exit. */

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>

#include "gx.h"

extern vcpuid_t max_vcpuid;
extern int guest_bitness;

static void
prnt_32regs(struct xg_gdb_regs32 *r32p)
{
    printf("eip:%08x esp:%08x flags:%08x\n", r32p->eip, r32p->esp,
           r32p->eflags);
    printf("eax:%08x ebx:%08x ecx:%08x edx:%08x\n", r32p->eax, 
           r32p->ebx, r32p->ecx, r32p->edx);
    printf("esi:%08x edi:%08x ebp:%08x\n", r32p->esi, r32p->edi, 
           r32p->ebp);
    printf("cs:%x ds:%x fs:%x gs:%x\n", r32p->cs, r32p->ds, r32p->fs, 
           r32p->gs);
    printf("\n");
}

static void
prnt_64regs(struct xg_gdb_regs64 *r64p)
{
    printf("rip:"XGF64" rsp:"XGF64" flags:"XGF64"\n", r64p->rip, r64p->rsp,
           r64p->rflags);
    printf("rax:"XGF64" rbx:"XGF64" rcx:"XGF64"\n", r64p->rax, r64p->rbx,
           r64p->rcx);
    printf("rdx:"XGF64" rsi:"XGF64" rdi:"XGF64"\n", r64p->rdx, r64p->rsi,
           r64p->rdi);
    printf("r08:"XGF64" r09:"XGF64" r10:"XGF64"\n", r64p->r8, r64p->r9,
           r64p->r10);
    printf("r11:"XGF64" r12:"XGF64" r13:"XGF64"\n", r64p->r11, r64p->r12,
           r64p->r13);
    printf("r14:"XGF64" r15:"XGF64" rbp:"XGF64"\n", r64p->r14, r64p->r15,
           r64p->rbp);
    printf("cs:"XGF64" ds:"XGF64" fs:"XGF64" gs:"XGF64"\n", r64p->cs, 
           r64p->ds, r64p->fs, r64p->gs);
    printf("\n");
}


static void
prnt_call_trace32(uint32_t ip, uint32_t sp)
{
    int stack_max=10;        /* try to print upto 10 entries if possible */
    uint32_t loopmax=0, val;

    printf("Call Trace:\n");
    printf("   [%08x]\n", ip);

    while(stack_max > 0) {
        if (xg_read_mem((uint64_t)sp, (char *)&val, sizeof(val),0) != 0)
            return;
        if (val > 0x0c000000) {              /* kernel addr */
            printf("   [%08x]\n", val);
            --stack_max;
        }
        sp += sizeof(sp);
        if (++loopmax > 10000)               /* don't go forever */
            break;
    }
}

static void
prnt_call_trace64(uint64_t ip, uint64_t sp)
{
    int stack_max=10;        /* try to print upto 10 entries if possible */
    uint64_t loopmax=0, val;

    printf("Call Trace:\n");
    printf("   ["XGF64"]\n", ip);

    while(stack_max > 0) {
        if (xg_read_mem(sp, (char *)&val, sizeof(val),0) != 0)
            return;
        if (val > 0xffffffff80000000UL) {    /* kernel addr */
            printf("   ["XGF64"]\n", val);
            --stack_max;
        }
        sp += sizeof(sp);
        if (++loopmax > 10000)               /* don't go forever */
            break;
    }
}

static int
prnt_vcpu_context(vcpuid_t vcpuid)
{
    union xg_gdb_regs gregs;
    int rc;

    printf("\n--> VCPU:%d\n", vcpuid);
    rc = xg_regs_read(XG_GPRS, vcpuid, &gregs, guest_bitness);
    if (rc) {
        gxprt("ERROR: failed to read regs. errno:%d\n", errno);
        return 1;
    }
    if (guest_bitness==32) {
        prnt_32regs(&gregs.gregs_32);
        prnt_call_trace32(gregs.gregs_32.eip, gregs.gregs_32.esp);
    } else {
        prnt_64regs(&gregs.gregs_64);
        prnt_call_trace64(gregs.gregs_64.rip, gregs.gregs_64.rsp);
    }
    return 0;
}

/* vcpuid is already checked to be <= max_vcpuid */
int
gx_local_cmd(domid_t domid, vcpuid_t vcpuid)
{
    printf("===> Context for DOMID:%d\n", domid);
    if (vcpuid == -1) {
        int i;
        for (i=0; i <= max_vcpuid; i++)
            prnt_vcpu_context(i);
    } else
        prnt_vcpu_context(vcpuid);
    return 0;
}
