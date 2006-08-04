#ifndef _XEN_UA64_PRIVOP_STAT_H
#define _XEN_UA64_PRIVOP_STAT_H
#include <public/arch-ia64.h>

extern int dump_privop_counts_to_user(char *, int);
extern int zero_privop_counts_to_user(char *, int);

#define PRIVOP_ADDR_COUNT

#ifdef PRIVOP_ADDR_COUNT

/* INST argument of PRIVOP_COUNT_ADDR.  */
#define _GET_IFA 0
#define _THASH 1
#define	PRIVOP_COUNT_ADDR(regs,inst) privop_count_addr(regs->cr_iip,inst)
extern void privop_count_addr(unsigned long addr, int inst);

#else
#define	PRIVOP_COUNT_ADDR(x,y) do {} while (0)
#endif

#endif /* _XEN_UA64_PRIVOP_STAT_H */
