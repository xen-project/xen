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

extern int mtrr_add(unsigned long base, unsigned long size,
                    unsigned int type, char increment);
extern int mtrr_add_page(unsigned long base, unsigned long size,
                         unsigned int type, char increment);
extern int mtrr_del(int reg, unsigned long base, unsigned long size);
extern int mtrr_del_page(int reg, unsigned long base, unsigned long size);
extern void mtrr_centaur_report_mcr(int mcr, u32 lo, u32 hi);

#endif /* __ASM_X86_MTRR_H__ */
