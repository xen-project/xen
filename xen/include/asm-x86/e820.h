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

#endif /*__E820_HEADER*/
