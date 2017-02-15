/*
 * xen/arch/arm/vuart.c
 *
 * Virtual UART Emulator.
 *
 * This emulator uses the information from dtuart. This is not intended to be
 * a full emulation of an UART device. Rather it is intended to provide a
 * sufficient veneer of one that early code (such as Linux's boot time
 * decompressor) which hardcodes output directly to such a device are able to
 * make progress.
 *
 * The minimal register set to emulate an UART are:
 *  - Single byte transmit register
 *  - Single status register
 *
 * /!\ This device is not intended to be enumerable or exposed to the OS
 * (e.g. via Device Tree).
 *
 * Julien Grall <julien.grall@linaro.org>
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
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/ctype.h>
#include <xen/serial.h>
#include <asm/mmio.h>
#include <xen/perfc.h>

#include "vuart.h"

#define domain_has_vuart(d) ((d)->arch.vuart.info != NULL)

static int vuart_mmio_read(struct vcpu *v, mmio_info_t *info,
                           register_t *r, void *priv);
static int vuart_mmio_write(struct vcpu *v, mmio_info_t *info,
                            register_t r, void *priv);

static const struct mmio_handler_ops vuart_mmio_handler = {
    .read  = vuart_mmio_read,
    .write = vuart_mmio_write,
};

int domain_vuart_init(struct domain *d)
{
    ASSERT( is_hardware_domain(d) );

    d->arch.vuart.info = serial_vuart_info(SERHND_DTUART);
    if ( !d->arch.vuart.info )
        return 0;

    spin_lock_init(&d->arch.vuart.lock);
    d->arch.vuart.idx = 0;

    d->arch.vuart.buf = xzalloc_array(char, VUART_BUF_SIZE);
    if ( !d->arch.vuart.buf )
        return -ENOMEM;

    register_mmio_handler(d, &vuart_mmio_handler,
                          d->arch.vuart.info->base_addr,
                          d->arch.vuart.info->size,
                          NULL);

    return 0;
}

void domain_vuart_free(struct domain *d)
{
    if ( !domain_has_vuart(d) )
        return;

    xfree(d->arch.vuart.buf);
}

static void vuart_print_char(struct vcpu *v, char c)
{
    struct domain *d = v->domain;
    struct vuart *uart = &d->arch.vuart;

    /* Accept only printable characters, newline, and horizontal tab. */
    if ( !isprint(c) && (c != '\n') && (c != '\t') )
        return ;

    spin_lock(&uart->lock);
    uart->buf[uart->idx++] = c;
    if ( (uart->idx == (VUART_BUF_SIZE - 2)) || (c == '\n') )
    {
        if ( c != '\n' )
            uart->buf[uart->idx++] = '\n';
        uart->buf[uart->idx] = '\0';
        printk(XENLOG_G_DEBUG "DOM%u: %s", d->domain_id, uart->buf);
        uart->idx = 0;
    }
    spin_unlock(&uart->lock);
}

static int vuart_mmio_read(struct vcpu *v, mmio_info_t *info,
                           register_t *r, void *priv)
{
    struct domain *d = v->domain;
    paddr_t offset = info->gpa - d->arch.vuart.info->base_addr;

    perfc_incr(vuart_reads);

    /* By default zeroed the register */
    *r = 0;

    if ( offset == d->arch.vuart.info->status_off )
        /* All holding registers empty, ready to send etc */
        *r = d->arch.vuart.info->status;

    return 1;
}

static int vuart_mmio_write(struct vcpu *v, mmio_info_t *info,
                            register_t r, void *priv)
{
    struct domain *d = v->domain;
    paddr_t offset = info->gpa - d->arch.vuart.info->base_addr;

    perfc_incr(vuart_writes);

    if ( offset == d->arch.vuart.info->data_off )
        /* ignore any status bits */
        vuart_print_char(v, r & 0xFF);

    return 1;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

