#ifndef __ARM_SHORT_DESC_H__
#define __ARM_SHORT_DESC_H__

/*
 * First level translation table descriptor types used by the AArch32
 * short-descriptor translation table format.
 */
#define L1DESC_INVALID                      (0)
#define L1DESC_PAGE_TABLE                   (1)
#define L1DESC_SECTION                      (2)
#define L1DESC_SECTION_PXN                  (3)

/* Defines for section and supersection shifts. */
#define L1DESC_SECTION_SHIFT                (20)
#define L1DESC_SUPERSECTION_SHIFT           (24)
#define L1DESC_SUPERSECTION_EXT_BASE1_SHIFT (32)
#define L1DESC_SUPERSECTION_EXT_BASE2_SHIFT (36)

/* Second level translation table descriptor types. */
#define L2DESC_INVALID                      (0)

/* Defines for small (4K) and large page (64K) shifts. */
#define L2DESC_SMALL_PAGE_SHIFT             (12)
#define L2DESC_LARGE_PAGE_SHIFT             (16)

/*
 * Comprises bits of the level 1 short-descriptor format representing
 * a section.
 */
typedef struct __packed {
    bool pxn:1;                 /* Privileged Execute Never */
    bool sec:1;                 /* == 1 if section or supersection */
    bool b:1;                   /* Bufferable */
    bool c:1;                   /* Cacheable */
    bool xn:1;                  /* Execute Never */
    unsigned int dom:4;         /* Domain field */
    bool impl:1;                /* Implementation defined */
    unsigned int ap:2;          /* AP[1:0] */
    unsigned int tex:3;         /* TEX[2:0] */
    bool ro:1;                  /* AP[2] */
    bool s:1;                   /* Shareable */
    bool ng:1;                  /* Non-global */
    bool supersec:1;            /* Must be 0 for sections */
    bool ns:1;                  /* Non-secure */
    unsigned int base:12;       /* Section base address */
} short_desc_l1_sec_t;

/*
 * Comprises bits of the level 1 short-descriptor format representing
 * a supersection.
 */
typedef struct __packed {
    bool pxn:1;                 /* Privileged Execute Never */
    bool sec:1;                 /* == 1 if section or supersection */
    bool b:1;                   /* Bufferable */
    bool c:1;                   /* Cacheable */
    bool xn:1;                  /* Execute Never */
    unsigned int extbase2:4;    /* Extended base address, PA[39:36] */
    bool impl:1;                /* Implementation defined */
    unsigned int ap:2;          /* AP[1:0] */
    unsigned int tex:3;         /* TEX[2:0] */
    bool ro:1;                  /* AP[2] */
    bool s:1;                   /* Shareable */
    bool ng:1;                  /* Non-global */
    bool supersec:1;            /* Must be 0 for sections */
    bool ns:1;                  /* Non-secure */
    unsigned int extbase1:4;    /* Extended base address, PA[35:32] */
    unsigned int base:8;        /* Supersection base address */
} short_desc_l1_supersec_t;

/*
 * Comprises bits of the level 2 short-descriptor format representing
 * a small page.
 */
typedef struct __packed {
    bool xn:1;                  /* Execute Never */
    bool page:1;                /* ==1 if small page */
    bool b:1;                   /* Bufferable */
    bool c:1;                   /* Cacheable */
    unsigned int ap:2;          /* AP[1:0] */
    unsigned int tex:3;         /* TEX[2:0] */
    bool ro:1;                  /* AP[2] */
    bool s:1;                   /* Shareable */
    bool ng:1;                  /* Non-global */
    unsigned int base:20;       /* Small page base address */
} short_desc_l2_page_t;

/*
 * Comprises bits of the level 2 short-descriptor format representing
 * a large page.
 */
typedef struct __packed {
    bool lpage:1;               /* ==1 if large page */
    bool page:1;                /* ==0 if large page */
    bool b:1;                   /* Bufferable */
    bool c:1;                   /* Cacheable */
    unsigned int ap:2;          /* AP[1:0] */
    unsigned int sbz:3;         /* Should be zero */
    bool ro:1;                  /* AP[2] */
    bool s:1;                   /* Shareable */
    bool ng:1;                  /* Non-global */
    unsigned int tex:3;         /* TEX[2:0] */
    bool xn:1;                  /* Execute Never */
    unsigned int base:16;       /* Large page base address */
} short_desc_l2_lpage_t;

/*
 * Comprises the bits required to walk page tables adhering to the
 * short-descriptor translation table format.
 */
typedef struct __packed {
    unsigned int dt:2;          /* Descriptor type */
    unsigned int pad1:8;
    unsigned int base:22;       /* Base address of block or next table */
} short_desc_walk_t;

/*
 * Represents page table entries adhering to the short-descriptor translation
 * table format.
 */
typedef union {
    uint32_t bits;
    short_desc_walk_t walk;
    short_desc_l1_sec_t sec;
    short_desc_l1_supersec_t supersec;
    short_desc_l2_page_t pg;
    short_desc_l2_lpage_t lpg;
} short_desc_t;

#endif /* __ARM_SHORT_DESC_H__ */
