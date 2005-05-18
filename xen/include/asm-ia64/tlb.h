#ifndef XEN_ASM_IA64_TLB_H
#define XEN_ASM_IA64_TLB_H

#define	NITRS	8
#define NDTRS	8

typedef struct {
    union {
        struct {
            unsigned long p    :  1; // 0
            unsigned long      :  1; // 1
            unsigned long ma   :  3; // 2-4
            unsigned long a    :  1; // 5
            unsigned long d    :  1; // 6
            unsigned long pl   :  2; // 7-8
            unsigned long ar   :  3; // 9-11
            unsigned long ppn  : 38; // 12-49
            unsigned long      :  2; // 50-51
            unsigned long ed   :  1; // 52
        };
        unsigned long page_flags;
    };

    union {
        struct {
            unsigned long      :  2; // 0-1
            unsigned long ps   :  6; // 2-7
            unsigned long key  : 24; // 8-31
            unsigned long      : 32; // 32-63
        };
        unsigned long itir;
    };

    unsigned long vadr;
    unsigned long rid;
} TR_ENTRY;

#ifdef CONFIG_VTI
typedef union {
        unsigned long   value;
        struct {
                uint64_t ve : 1;
                uint64_t rv1 : 1;
                uint64_t ps  : 6;
                uint64_t rid : 24;
                uint64_t rv2 : 32;
        };
} rr_t;
#endif // CONFIG_VTI

#endif
