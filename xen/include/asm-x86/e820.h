#ifndef __E820_HEADER
#define __E820_HEADER

#include <asm/page.h>

#define E820MAX	32

#define E820_RAM	1
#define E820_RESERVED	2
#define E820_ACPI	3
#define E820_NVS	4

#ifndef __ASSEMBLY__
struct e820entry {
    u64 addr;
    u64 size;
    u32 type;
} __attribute__((packed));

struct e820map {
    int nr_map;
    struct e820entry map[E820MAX];
};

extern unsigned long init_e820(struct e820entry *, int);
extern struct e820map e820;

#endif /*!__ASSEMBLY__*/

#define PFN_DOWN(_p)  ((_p)&PAGE_MASK)
#define PFN_UP(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)

#endif /*__E820_HEADER*/
