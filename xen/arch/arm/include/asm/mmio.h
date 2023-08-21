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
#include <xen/rwlock.h>

#include <asm/hsr.h>

#define MAX_IO_HANDLER  16

enum instr_decode_state
{
    INSTR_ERROR,                    /* Error encountered while decoding instr */
    INSTR_VALID,                    /* ISS is valid, so no need to decode */
    /*
     * Instruction is decoded successfully. It is a ldr/str post indexing
     * instruction.
     */
    INSTR_LDR_STR_POSTINDEXING,
    INSTR_CACHE,                    /* Cache Maintenance instr */
};

typedef struct
{
    struct hsr_dabt dabt;
    struct instr_details {
        unsigned long rn:5;
        signed int imm9:9;
        enum instr_decode_state state;
    } dabt_instr;
    paddr_t gpa;
} mmio_info_t;

enum io_state
{
    IO_ABORT,       /* The IO was handled by the helper and led to an abort. */
    IO_HANDLED,     /* The IO was successfully handled by the helper. */
    IO_UNHANDLED,   /* The IO was not handled by the helper. */
    IO_RETRY,       /* Retry the emulation for some reason */
};

typedef int (*mmio_read_t)(struct vcpu *v, mmio_info_t *info,
                           register_t *r, void *priv);
typedef int (*mmio_write_t)(struct vcpu *v, mmio_info_t *info,
                            register_t r, void *priv);

struct mmio_handler_ops {
    mmio_read_t read;
    mmio_write_t write;
};

struct mmio_handler {
    paddr_t addr;
    paddr_t size;
    const struct mmio_handler_ops *ops;
    void *priv;
};

struct vmmio {
    unsigned int num_entries;
    unsigned int max_num_entries;
    rwlock_t lock;
    struct mmio_handler *handlers;
};

enum io_state try_handle_mmio(struct cpu_user_regs *regs,
                              mmio_info_t *info);
void register_mmio_handler(struct domain *d,
                           const struct mmio_handler_ops *ops,
                           paddr_t addr, paddr_t size, void *priv);
int domain_io_init(struct domain *d, unsigned int max_count);
void domain_io_free(struct domain *d);

void try_decode_instruction(const struct cpu_user_regs *regs,
                            mmio_info_t *info);

#endif  /* __ASM_ARM_MMIO_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
