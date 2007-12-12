#ifndef __ASM_X86_MTRR_H__
#define __ASM_X86_MTRR_H__

#include <xen/config.h>

/* These are the region types. They match the architectural specification. */
#define MTRR_TYPE_UNCACHABLE 0
#define MTRR_TYPE_WRCOMB     1
#define MTRR_TYPE_WRTHROUGH  4
#define MTRR_TYPE_WRPROT     5
#define MTRR_TYPE_WRBACK     6
#define MTRR_NUM_TYPES       7
#define MEMORY_NUM_TYPES     MTRR_NUM_TYPES

#define MTRR_PHYSMASK_VALID_BIT  11
#define MTRR_PHYSMASK_SHIFT      12

#define MTRR_PHYSBASE_TYPE_MASK  0xff   /* lowest 8 bits */
#define MTRR_PHYSBASE_SHIFT      12
#define MTRR_VCNT            8

#define NORMAL_CACHE_MODE          0
#define NO_FILL_CACHE_MODE         2

enum {
    PAT_TYPE_UNCACHABLE=0,
    PAT_TYPE_WRCOMB=1,
    PAT_TYPE_RESERVED=2,
    PAT_TYPE_WRTHROUGH=4,
    PAT_TYPE_WRPROT=5,
    PAT_TYPE_WRBACK=6,
    PAT_TYPE_UC_MINUS=7,
    PAT_TYPE_NUMS
};

#define INVALID_MEM_TYPE PAT_TYPE_NUMS

/* In the Intel processor's MTRR interface, the MTRR type is always held in
   an 8 bit field: */
typedef u8 mtrr_type;

struct mtrr_var_range {
	u32 base_lo;
	u32 base_hi;
	u32 mask_lo;
	u32 mask_hi;
};

#define NUM_FIXED_RANGES 88
#define NUM_FIXED_MSR 11
struct mtrr_state {
	struct mtrr_var_range *var_ranges;
	mtrr_type fixed_ranges[NUM_FIXED_RANGES];
	unsigned char enabled;
	unsigned char have_fixed;
	mtrr_type def_type;

	u64       mtrr_cap;
	/* ranges in var MSRs are overlapped or not:0(no overlapped) */
	bool_t    overlapped;
	bool_t    is_initialized;
};

extern void mtrr_save_fixed_ranges(void *);
extern void mtrr_save_state(void);
extern int mtrr_add(unsigned long base, unsigned long size,
                    unsigned int type, char increment);
extern int mtrr_add_page(unsigned long base, unsigned long size,
                         unsigned int type, char increment);
extern int mtrr_del(int reg, unsigned long base, unsigned long size);
extern int mtrr_del_page(int reg, unsigned long base, unsigned long size);
extern void mtrr_centaur_report_mcr(int mcr, u32 lo, u32 hi);

#endif /* __ASM_X86_MTRR_H__ */
