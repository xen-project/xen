/*
 * memory related definitions needed for userspace domain builder dom0 application. these _need_ to
 * be kept in sync with the kernel .h files they were copied over from or something horrible will
 * happen. remmember: god kills a kitten every time you forget to keep these in sync.
 * 
 * KAF: Boris, these constants are all fixed by x86 hardware. So the kittens are safe for now :-)
 * 
 * Copyright 2002 by B Dragovic
 */

/* copied over from hypervisor: include/asm-i386/page.h */

#define _PAGE_PRESENT   0x001
#define _PAGE_RW    0x002
#define _PAGE_USER  0x004
#define _PAGE_PWT   0x008
#define _PAGE_PCD   0x010
#define _PAGE_ACCESSED  0x020
#define _PAGE_DIRTY 0x040
#define _PAGE_PAT       0x080
#define _PAGE_PSE   0x080
#define _PAGE_GLOBAL    0x100


#define L1_PAGETABLE_SHIFT       12
#define L2_PAGETABLE_SHIFT       22
 
#define ENTRIES_PER_L1_PAGETABLE 1024
#define ENTRIES_PER_L2_PAGETABLE 1024
 
#define PAGE_SHIFT              L1_PAGETABLE_SHIFT
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#define PAGE_MASK               (~(PAGE_SIZE-1))

typedef struct { unsigned long l1_lo; } l1_pgentry_t;
typedef struct { unsigned long l2_lo; } l2_pgentry_t;

#define l1_table_offset(_a) \
          (((_a) >> L1_PAGETABLE_SHIFT) & (ENTRIES_PER_L1_PAGETABLE - 1))
#define l2_table_offset(_a) \
          ((_a) >> L2_PAGETABLE_SHIFT)

/* local definitions */

#define nr_2_page(x) (x << PAGE_SHIFT)
