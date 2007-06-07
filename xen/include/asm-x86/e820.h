#ifndef __E820_HEADER
#define __E820_HEADER

#include <public/hvm/e820.h>

#define E820MAX	128

struct e820map {
    int nr_map;
    struct e820entry map[E820MAX];
};

extern unsigned long init_e820(struct e820entry *, int *);
extern struct e820map e820;

/* These symbols live in the boot trampoline. */
extern struct e820entry e820map[];
extern unsigned char e820nr;
extern unsigned int lowmem_kb, highmem_kb;

#endif /*__E820_HEADER*/
