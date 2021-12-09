/*
 * xen/arch/arm/vpci.h
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

#ifndef __ARCH_ARM_VPCI_H__
#define __ARCH_ARM_VPCI_H__

#ifdef CONFIG_HAS_VPCI
int domain_vpci_init(struct domain *d);
unsigned int domain_vpci_get_num_mmio_handlers(struct domain *d);
#else
static inline int domain_vpci_init(struct domain *d)
{
    return 0;
}

static inline unsigned int domain_vpci_get_num_mmio_handlers(struct domain *d)
{
    return 0;
}
#endif

#endif /* __ARCH_ARM_VPCI_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
