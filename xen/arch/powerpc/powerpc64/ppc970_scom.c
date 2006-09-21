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
#include <xen/errno.h>
#include <asm/delay.h>

#define SPRN_SCOMC 276
#define SPRN_SCOMD 277
#define SCOMC_READ 1
#define SCOMC_WRITE (!(SCOMC_READ))

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


static inline int read_scom(uint addr, ulong *d)
{
    union scomc c;
    ulong flags;

    /* drop the low 8bits (including parity) */
    addr >>= 8;

    /* these give iface errors because the address is ambiguous after
     * the above bit dropping */
    BUG_ON(addr == 0x8000);

    for (;;) {
        c.word = 0;
        c.bits.addr = addr;
        c.bits.RW = SCOMC_READ;

        local_irq_save(flags);
        asm volatile (
            "sync         \n\t"
            "mtspr %2, %0 \n\t"
            "isync        \n\t"
            "mfspr %1, %3 \n\t"
            "isync        \n\t"
            "mfspr %0, %2 \n\t"
            "isync        \n\t"
            : "+r" (c.word), "=r" (*d)
            : "i"(SPRN_SCOMC), "i"(SPRN_SCOMD));

        local_irq_restore(flags);
        /* WARNING! older 970s (pre FX) shift the bits right 1 position */

        if (!c.bits.failure)
            return 0;

        /* deal with errors */
        /* has SCOM been disabled? */
        if (c.bits.disabled)
            return -ENOSYS;

        /* we were passed a bad addr return -1 */
        if (c.bits.addr_error)
            return -EINVAL;

        /* this is way bad and we will checkstop soon */
        BUG_ON(c.bits.proto_error);

        if (c.bits.iface_error)
            udelay(10);
    }
}

static inline int write_scom(uint addr, ulong d)
{
    union scomc c;
    ulong flags;

    /* drop the low 8bits (including parity) */
    addr >>= 8;

    /* these give iface errors because the address is ambiguous after
     * the above bit dropping */
    BUG_ON(addr == 0x8000);

    for (;;) {
        c.word = 0;
        c.bits.addr = addr;
        c.bits.RW = SCOMC_WRITE;

        local_irq_save(flags);
        asm volatile(
            "sync         \n\t"
            "mtspr %3, %1 \n\t"
            "isync        \n\t"
            "mtspr %2, %0 \n\t"
            "isync        \n\t"
            "mfspr %0, %2 \n\t"
            "isync        \n\t"
            : "+r" (c.word)
            : "r" (d), "i"(SPRN_SCOMC), "i"(SPRN_SCOMD));
        local_irq_restore(flags);

        if (!c.bits.failure)
            return 0;

        /* has SCOM been disabled? */
        if (c.bits.disabled)
            return -ENOSYS;

        /* we were passed a bad addr return -1 */
        if (c.bits.addr_error)
            return -EINVAL;

        /* this is way bad and we will checkstop soon */
        BUG_ON(c.bits.proto_error);

        /* check for iface and retry */
        if (c.bits.iface_error)
            udelay(10);
    }
}

/* SCOMC addresses are 16bit but we are given 24 bits in the
 * books. The low oerder 8 bits are some kinda parity thin and should
 * be ignored */
#define SCOM_AMCS_REG      0x022601
#define SCOM_AMCS_AND_MASK 0x022700
#define SCOM_AMCS_OR_MASK  0x022800
#define SCOM_CMCE          0x030901
#define SCOM_PMCR          0x400801
#define SCOM_PTSR          0x408001

/* cannot access these since only top 16bits are considered */
#define SCOM_STATUS        0x800003

void cpu_scom_init(void)
{
    ulong val;
    console_start_sync();
    if (!read_scom(SCOM_PTSR, &val))
        printk("SCOM PTSR: 0x%016lx\n", val);

    console_end_sync();
}
