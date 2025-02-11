/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * System resource description.
 */
#ifndef XEN__RESOURCE_H
#define XEN__RESOURCE_H

#define IORESOURCE_BITS         0x000000FFU      /* Bus-specific bits */

#define IORESOURCE_TYPE_BITS    0x00001F00U      /* Resource type */
#define IORESOURCE_IO           0x00000100U      /* PCI/ISA I/O ports */
#define IORESOURCE_MEM          0x00000200U
#define IORESOURCE_REG          0x00000300U      /* Register offsets */
#define IORESOURCE_IRQ          0x00000400U
#define IORESOURCE_DMA          0x00000800U
#define IORESOURCE_BUS          0x00001000U

#define IORESOURCE_PREFETCH     0x00002000U      /* No side effects */
#define IORESOURCE_READONLY     0x00004000U
#define IORESOURCE_CACHEABLE    0x00008000U
#define IORESOURCE_RANGELENGTH  0x00010000U
#define IORESOURCE_SHADOWABLE   0x00020000U

#define IORESOURCE_UNKNOWN      (~0U)

struct resource {
    paddr_t addr;
    paddr_t size;
    unsigned int type;
};

#define resource_size(res)      ((res)->size)

#endif /* XEN__RESOURCE_H */
