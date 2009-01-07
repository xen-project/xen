#ifndef __HVMLOADER_E820_H__
#define __HVMLOADER_E820_H__

#include <xen/hvm/e820.h>

/*
 * PC BIOS standard E820 types and structure.
 */
#define E820_RAM          1
#define E820_RESERVED     2
#define E820_ACPI         3
#define E820_NVS          4

struct e820entry {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
} __attribute__((packed));

#define E820_NR ((uint16_t *)(E820_PHYSICAL_ADDRESS + E820_NR_OFFSET))
#define E820    ((struct e820entry *)(E820_PHYSICAL_ADDRESS + E820_OFFSET))

#endif /* __HVMLOADER_E820_H__ */
