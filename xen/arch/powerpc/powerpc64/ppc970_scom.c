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
 * Copyright (C) IBM Corp. 2006
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/console.h>

#define SPRN_SCOMC 276
#define SPRN_SCOMD 277

static inline void mtscomc(ulong scomc)
{
    __asm__ __volatile__ ("mtspr %1, %0" : : "r" (scomc), "i"(SPRN_SCOMC));
}

static inline ulong mfscomc(void)
{
    ulong scomc;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r" (scomc): "i"(SPRN_SCOMC));
    return scomc;
}

static inline void mtscomd(ulong scomd)
{
    __asm__ __volatile__ ("mtspr %1, %0" : : "r" (scomd), "i"(SPRN_SCOMD));
}

static inline ulong mfscomd(void)
{
    ulong scomd;
    __asm__ __volatile__ ("mfspr %0, %1" : "=r" (scomd): "i"(SPRN_SCOMD));
    return scomd;
}

union scomc {
    struct scomc_bits {
        ulong _reserved_0_31: 32;
        ulong addr:           16;
        ulong RW:              1;
        ulong _reserved_49_55: 7;
        ulong _reserved_56:    1;
        ulong proto_error:     1;
        ulong addr_error:      1;
        ulong iface_error:     1;
        ulong disabled:        1;
        ulong _reserved_61_62: 2;
        ulong failure:         1;
    } bits;
    ulong word;
};


static inline ulong read_scom(ulong addr)
{
    union scomc c;
    ulong d;

    c.word = 0;
    c.bits.addr = addr;
    c.bits.RW = 0;

    mtscomc(c.word);
    d = mfscomd();
    c.word = mfscomc();
    if (c.bits.failure)
        panic("scom status: 0x%016lx\n", c.word);

    return d;
}

static inline void write_scom(ulong addr, ulong val)
{
    union scomc c;

    c.word = 0;
    c.bits.addr = addr;
    c.bits.RW = 1;

    mtscomd(val);
    mtscomc(c.word);
    c.word = mfscomc();
    if (c.bits.failure)
        panic("scom status: 0x%016lx\n", c.word);
}

#define SCOM_AMCS_REG      0x022601
#define SCOM_AMCS_AND_MASK 0x022700
#define SCOM_AMCS_OR_MASK  0x022800
#define SCOM_CMCE          0x030901
#define SCOM_PMCR          0x400801

void cpu_scom_init(void)
{
#ifdef not_yet
    console_start_sync();
    printk("scom PMCR: 0x%016lx\n", read_scom(SCOM_PMCR));
    console_end_sync();
#endif
}
