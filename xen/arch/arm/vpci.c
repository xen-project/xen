/*
 * xen/arch/arm/vpci.c
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
#include <xen/sched.h>
#include <xen/vpci.h>

#include <asm/mmio.h>

static int vpci_mmio_read(struct vcpu *v, mmio_info_t *info,
                          register_t *r, void *p)
{
    pci_sbdf_t sbdf;
    /* data is needed to prevent a pointer cast on 32bit */
    unsigned long data;

    /* We ignore segment part and always handle segment 0 */
    sbdf.sbdf = VPCI_ECAM_BDF(info->gpa);

    if ( vpci_ecam_read(sbdf, ECAM_REG_OFFSET(info->gpa),
                        1U << info->dabt.size, &data) )
    {
        *r = data;
        return 1;
    }

    *r = ~0ul;

    return 0;
}

static int vpci_mmio_write(struct vcpu *v, mmio_info_t *info,
                           register_t r, void *p)
{
    pci_sbdf_t sbdf;

    /* We ignore segment part and always handle segment 0 */
    sbdf.sbdf = VPCI_ECAM_BDF(info->gpa);

    return vpci_ecam_write(sbdf, ECAM_REG_OFFSET(info->gpa),
                           1U << info->dabt.size, r);
}

static const struct mmio_handler_ops vpci_mmio_handler = {
    .read  = vpci_mmio_read,
    .write = vpci_mmio_write,
};

int domain_vpci_init(struct domain *d)
{
    if ( !has_vpci(d) )
        return 0;

    register_mmio_handler(d, &vpci_mmio_handler,
                          GUEST_VPCI_ECAM_BASE, GUEST_VPCI_ECAM_SIZE, NULL);

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

