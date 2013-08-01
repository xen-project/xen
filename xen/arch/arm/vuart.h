/*
 * xen/arch/arm/vuart.h
 *
 * Virtual UART Emulation Support
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

#ifndef __ARCH_ARM_VUART_H__
#define __ARCH_ARM_VUART_H__

int domain_vuart_init(struct domain *d);
void domain_vuart_free(struct domain *d);

#endif /* __ARCH_ARM_VUART_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
