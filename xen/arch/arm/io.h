/*
 * xen/arch/arm/io.h
 *
 * ARM I/O handlers
 *
 * Copyright (c) 2011 Citrix Systems.
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

#ifndef __ARCH_ARM_IO_H__
#define __ARCH_ARM_IO_H__

#include <xen/lib.h>
#include <asm/processor.h>

typedef struct
{
    struct hsr_dabt dabt;
    uint32_t gva;
    paddr_t gpa;
} mmio_info_t;

typedef int (*mmio_read_t)(struct vcpu *v, mmio_info_t *info);
typedef int (*mmio_write_t)(struct vcpu *v, mmio_info_t *info);
typedef int (*mmio_check_t)(struct vcpu *v, paddr_t addr);

struct mmio_handler {
    mmio_check_t check_handler;
    mmio_read_t read_handler;
    mmio_write_t write_handler;
};

extern const struct mmio_handler vgic_distr_mmio_handler;
extern const struct mmio_handler uart0_mmio_handler;

extern int handle_mmio(mmio_info_t *info);

#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
