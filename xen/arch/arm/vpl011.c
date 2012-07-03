/*
 * xen/arch/arm/vpl011.c
 *
 * ARM PL011 UART Emulator (DEBUG)
 *
 * Ian Campbell <ian.campbell@citrix.com>
 * Copyright (c) 2012 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * This is not intended to be a full emulation of a PL011
 * device. Rather it is intended to provide a sufficient veneer of one
 * that early code (such as Linux's boot time decompressor) which
 * hardcodes output directly to such a device are able to make progress.
 *
 * This device is not intended to be enumerable or exposed to the OS
 * (e.g. via Device Tree).
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/ctype.h>

#include "io.h"

#define UART0_START 0x1c090000
#define UART0_END   (UART0_START+65536)

#define UARTDR 0x000
#define UARTFR 0x018

int domain_uart0_init(struct domain *d)
{
    ASSERT( d->domain_id );

    spin_lock_init(&d->arch.uart0.lock);
    d->arch.uart0.idx = 0;

    d->arch.uart0.buf = xzalloc_array(char, VPL011_BUF_SIZE);
    if ( !d->arch.uart0.buf )
        return -ENOMEM;

    return 0;

}

void domain_uart0_free(struct domain *d)
{
    xfree(d->arch.uart0.buf);
}

static void uart0_print_char(char c)
{
    struct vpl011 *uart = &current->domain->arch.uart0;

    /* Accept only printable characters, newline, and horizontal tab. */
    if ( !isprint(c) && (c != '\n') && (c != '\t') )
        return ;

    spin_lock(&uart->lock);
    uart->buf[uart->idx++] = c;
    if ( (uart->idx == (VPL011_BUF_SIZE - 2)) || (c == '\n') )
    {
        if ( c != '\n' )
            uart->buf[uart->idx++] = '\n';
        uart->buf[uart->idx] = '\0';
        printk(XENLOG_G_DEBUG "DOM%u: %s",
               current->domain->domain_id, uart->buf);
        uart->idx = 0;
    }
    spin_unlock(&uart->lock);
}

static int uart0_mmio_check(struct vcpu *v, paddr_t addr)
{
    return addr >= UART0_START && addr < UART0_END;
}

static int uart0_mmio_read(struct vcpu *v, mmio_info_t *info)
{
    struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    uint32_t *r = &regs->r0 + dabt.reg;
    int offset = (int)(info->gpa - UART0_START);

    switch ( offset )
    {
    case UARTDR:
        *r = 0;
        return 1;
    case UARTFR:
        *r = 0x87; /* All holding registers empty, ready to send etc */
        return 1;
    default:
        printk("VPL011: unhandled read r%d offset %#08x\n",
               dabt.reg, offset);
        domain_crash_synchronous();
    }
}

static int uart0_mmio_write(struct vcpu *v, mmio_info_t *info)
{
    struct hsr_dabt dabt = info->dabt;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    uint32_t *r = &regs->r0 + dabt.reg;
    int offset = (int)(info->gpa - UART0_START);

    switch ( offset )
    {
    case UARTDR:
        /* ignore any status bits */
        uart0_print_char((int)((*r) & 0xFF));
        return 1;
    case UARTFR:
        /* Silently ignore */
        return 1;
    default:
        printk("VPL011: unhandled write r%d=%"PRIx32" offset %#08x\n",
               dabt.reg, *r, offset);
        domain_crash_synchronous();
    }
}

const struct mmio_handler uart0_mmio_handler = {
    .check_handler = uart0_mmio_check,
    .read_handler  = uart0_mmio_read,
    .write_handler = uart0_mmio_write,
};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

