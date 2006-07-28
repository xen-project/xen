#ifndef _XEN_UA64_PRIVOP_STAT_H
#define _XEN_UA64_PRIVOP_STAT_H
#include <public/arch-ia64.h>

extern int dump_privop_counts_to_user(char *, int);
extern int zero_privop_counts_to_user(char *, int);

#define PRIVOP_ADDR_COUNT

/* vcpu_translate hit with dtlb.  */
extern unsigned long dtlb_translate_count;

/* vcpu_translate hit with tr.  */
extern unsigned long tr_translate_count;

/* vcpu_translate in metaphysical mode.  */
extern unsigned long phys_translate_count;

extern unsigned long vhpt_translate_count;
extern unsigned long fast_vhpt_translate_count;
extern unsigned long recover_to_page_fault_count;
extern unsigned long recover_to_break_fault_count;
extern unsigned long idle_when_pending;
extern unsigned long pal_halt_light_count;
extern unsigned long context_switch_count;
extern unsigned long lazy_cover_count;

extern unsigned long slow_hyperpriv_cnt[HYPERPRIVOP_MAX+1];
extern unsigned long fast_hyperpriv_cnt[HYPERPRIVOP_MAX+1];

extern unsigned long slow_reflect_count[0x80];
extern unsigned long fast_reflect_count[0x80];

struct privop_counters {
	unsigned long mov_to_ar_imm;
	unsigned long mov_to_ar_reg;
	unsigned long mov_from_ar;
	unsigned long ssm;
	unsigned long rsm;
	unsigned long rfi;
	unsigned long bsw0;
	unsigned long bsw1;
	unsigned long cover;
	unsigned long fc;
	unsigned long cpuid;
	unsigned long Mpriv_cnt[64];

	unsigned long to_cr_cnt[128]; /* Number of mov to cr privop.  */
	unsigned long from_cr_cnt[128]; /* Number of mov from cr privop.  */
};

extern struct privop_counters privcnt;

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
