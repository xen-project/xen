#ifndef __E820_HEADER
#define __E820_HEADER

/*
 * PC BIOS standard E820 types and structure.
 */
#define E820_RAM          1
#define E820_RESERVED     2
#define E820_ACPI         3
#define E820_NVS          4
#define E820_UNUSABLE     5

struct __packed e820entry {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
};

#define E820MAX	1024

struct e820map {
    unsigned int nr_map;
    struct e820entry map[E820MAX];
};

extern int sanitize_e820_map(struct e820entry *biosmap, unsigned int *pnr_map);
extern int e820_all_mapped(u64 start, u64 end, unsigned type);
extern int reserve_e820_ram(struct e820map *e820, uint64_t s, uint64_t e);
extern int e820_change_range_type(
    struct e820map *e820, uint64_t s, uint64_t e,
    uint32_t orig_type, uint32_t new_type);
extern int e820_add_range(
    struct e820map *, uint64_t s, uint64_t e, uint32_t type);
extern unsigned long init_e820(const char *, struct e820map *);
extern struct e820map e820;
extern struct e820map e820_raw;

/* These symbols live in the boot trampoline. */
extern unsigned int lowmem_kb, highmem_kb;
unsigned int e820map_copy(struct e820entry *map, unsigned int limit);

#define copy_bios_e820 bootsym(e820map_copy)

#endif /*__E820_HEADER*/
