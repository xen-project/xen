/* SPDX-License-Identifier: MIT */

/*
 * xen/arch/riscv/include/asm/imsic.h
 *
 * RISC-V Incoming MSI Controller support
 *
 * (c) Microchip Technology Inc.
 */

#ifndef ASM_RISCV_IMSIC_H
#define ASM_RISCV_IMSIC_H

#include <xen/types.h>

#define IMSIC_MMIO_PAGE_SHIFT   12
#define IMSIC_MMIO_PAGE_SZ      (1UL << IMSIC_MMIO_PAGE_SHIFT)

#define IMSIC_MIN_ID            63
#define IMSIC_MAX_ID            2047

struct imsic_msi {
    paddr_t base_addr;
    unsigned long offset;
};

struct imsic_config {
    /* Base address */
    paddr_t base_addr;

    /* Bits representing Guest index, HART index, and Group index */
    unsigned int guest_index_bits;
    unsigned int hart_index_bits;
    unsigned int group_index_bits;
    unsigned int group_index_shift;

    /* IMSIC phandle */
    unsigned int phandle;

    /* Number of parent irq */
    unsigned int nr_parent_irqs;

    /* Number off interrupt identities */
    unsigned int nr_ids;

    /* MSI */
    const struct imsic_msi *msi;
};

struct dt_device_node;
int imsic_init(const struct dt_device_node *node);

const struct imsic_config *imsic_get_config(void);

#endif /* ASM_RISCV_IMSIC_H */
