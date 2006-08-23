#ifndef __XEN_PUBLIC_HVM_E820_H__
#define __XEN_PUBLIC_HVM_E820_H__

/* PC BIOS standard E820 types. */
#define E820_RAM          1
#define E820_RESERVED     2
#define E820_ACPI         3
#define E820_NVS          4

/* Xen HVM extended E820 types. */
#define E820_IO          16
#define E820_SHARED_PAGE 17
#define E820_XENSTORE    18
#define E820_BUFFERED_IO 19

/* E820 location in HVM virtual address space. */
#define E820_MAP_PAGE        0x00090000
#define E820_MAP_NR_OFFSET   0x000001E8
#define E820_MAP_OFFSET      0x000002D0

struct e820entry {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
} __attribute__((packed));

#define HVM_BELOW_4G_RAM_END        0xF0000000

#define HVM_BELOW_4G_MMIO_START     HVM_BELOW_4G_RAM_END
#define HVM_BELOW_4G_MMIO_LENGTH    ((1ULL << 32) - HVM_BELOW_4G_MMIO_START)

#endif /* __XEN_PUBLIC_HVM_E820_H__ */
