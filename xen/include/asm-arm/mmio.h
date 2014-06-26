/*
 * xen/include/asm-arm/mmio.h
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

#ifndef __ASM_ARM_MMIO_H__
#define __ASM_ARM_MMIO_H__

#include <xen/lib.h>
#include <asm/processor.h>
#include <asm/regs.h>

#define MAX_IO_HANDLER  16

typedef struct
{
    struct hsr_dabt dabt;
    vaddr_t gva;
    paddr_t gpa;
} mmio_info_t;

typedef int (*mmio_read_t)(struct vcpu *v, mmio_info_t *info);
typedef int (*mmio_write_t)(struct vcpu *v, mmio_info_t *info);
typedef int (*mmio_check_t)(struct vcpu *v, paddr_t addr);

struct mmio_handler_ops {
    mmio_read_t read_handler;
    mmio_write_t write_handler;
};

struct mmio_handler {
    paddr_t addr;
    paddr_t size;
    const struct mmio_handler_ops *mmio_handler_ops;
};

struct io_handler {
    int num_entries;
    spinlock_t lock;
    struct mmio_handler mmio_handlers[MAX_IO_HANDLER];
};

extern int handle_mmio(mmio_info_t *info);
void register_mmio_handler(struct domain *d,
                           const struct mmio_handler_ops *handle,
                           paddr_t addr, paddr_t size);
int domain_io_init(struct domain *d);

#endif  /* __ASM_ARM_MMIO_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
