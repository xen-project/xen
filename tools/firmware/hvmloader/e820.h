#ifndef __HVMLOADER_E820_H__
#define __HVMLOADER_E820_H__

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

#define E820MAX	128

struct e820map {
    unsigned int nr_map;
    struct e820entry map[E820MAX];
};

#endif /* __HVMLOADER_E820_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
