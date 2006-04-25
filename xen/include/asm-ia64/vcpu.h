#ifndef _XEN_IA64_VCPU_H
#define _XEN_IA64_VCPU_H

// TODO: Many (or perhaps most) of these should eventually be
// static inline functions

//#include "thread.h"
#include <asm/ia64_int.h>
#include <public/arch-ia64.h>
typedef	unsigned long UINT64;
typedef	unsigned int UINT;
typedef	int BOOLEAN;
struct vcpu;
typedef	struct vcpu VCPU;

typedef cpu_user_regs_t REGS;


/* Note: PSCB stands for Privilegied State Communication Block.  */
#define VCPU(_v,_x)	(_v->arch.privregs->_x)
#define PSCB(_v,_x) VCPU(_v,_x)
#define PSCBX(_v,_x) (_v->arch._x)

#define PRIVOP_ADDR_COUNT
#ifdef PRIVOP_ADDR_COUNT
#define _GET_IFA 0
#define _THASH 1
#define PRIVOP_COUNT_NINSTS 2
#define PRIVOP_COUNT_NADDRS 30

struct privop_addr_count {
	char *instname;
	unsigned long addr[PRIVOP_COUNT_NADDRS];
	unsigned long count[PRIVOP_COUNT_NADDRS];
	unsigned long overflow;
};
#endif

/* general registers */
extern UINT64 vcpu_get_gr(VCPU *vcpu, unsigned long reg);
extern IA64FAULT vcpu_get_gr_nat(VCPU *vcpu, unsigned long reg, UINT64 *val);
extern IA64FAULT vcpu_set_gr(VCPU *vcpu, unsigned long reg, UINT64 value, int nat);
extern IA64FAULT vcpu_get_fpreg(VCPU *vcpu, unsigned long reg, struct ia64_fpreg *val);

extern IA64FAULT vcpu_set_fpreg(VCPU *vcpu, unsigned long reg, struct ia64_fpreg *val);

/* application registers */
extern void vcpu_load_kernel_regs(VCPU *vcpu);
extern IA64FAULT vcpu_set_ar(VCPU *vcpu, UINT64 reg, UINT64 val);
extern IA64FAULT vcpu_get_ar(VCPU *vcpu, UINT64 reg, UINT64 *val);
/* psr */
extern BOOLEAN vcpu_get_psr_ic(VCPU *vcpu);
extern UINT64 vcpu_get_ipsr_int_state(VCPU *vcpu,UINT64 prevpsr);
extern IA64FAULT vcpu_get_psr(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_reset_psr_sm(VCPU *vcpu, UINT64 imm);
extern IA64FAULT vcpu_set_psr_sm(VCPU *vcpu, UINT64 imm);
extern IA64FAULT vcpu_set_psr_l(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_psr_i(VCPU *vcpu);
extern IA64FAULT vcpu_reset_psr_dt(VCPU *vcpu);
extern IA64FAULT vcpu_set_psr_dt(VCPU *vcpu);
/* control registers */
extern IA64FAULT vcpu_set_dcr(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_itm(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_iva(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_pta(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_ipsr(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_isr(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_iip(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_ifa(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_itir(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_iipa(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_ifs(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_iim(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_iha(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_lid(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_tpr(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_eoi(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_lrr0(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_lrr1(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_get_dcr(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_itm(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_iva(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_pta(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_ipsr(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_isr(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_iip(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_increment_iip(VCPU *vcpu);
extern IA64FAULT vcpu_get_ifa(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_itir(VCPU *vcpu, UINT64 *pval);
extern unsigned long vcpu_get_itir_on_fault(VCPU *vcpu, UINT64 ifa);
extern IA64FAULT vcpu_get_iipa(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_ifs(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_iim(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_iha(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_lid(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_tpr(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_irr0(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_irr1(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_irr2(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_irr3(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_lrr0(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_get_lrr1(VCPU *vcpu, UINT64 *pval);
/* interrupt registers */
extern void vcpu_pend_unspecified_interrupt(VCPU *vcpu);
extern UINT64 vcpu_check_pending_interrupts(VCPU *vcpu);
extern IA64FAULT vcpu_get_itv(VCPU *vcpu,UINT64 *pval);
extern IA64FAULT vcpu_get_pmv(VCPU *vcpu,UINT64 *pval);
extern IA64FAULT vcpu_get_cmcv(VCPU *vcpu,UINT64 *pval);
extern IA64FAULT vcpu_get_ivr(VCPU *vcpu, UINT64 *pval);
extern IA64FAULT vcpu_set_itv(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_pmv(VCPU *vcpu, UINT64 val);
extern IA64FAULT vcpu_set_cmcv(VCPU *vcpu, UINT64 val);
/* interval timer registers */
extern IA64FAULT vcpu_set_itc(VCPU *vcpu,UINT64 val);
extern UINT64 vcpu_timer_pending_early(VCPU *vcpu);
/* debug breakpoint registers */
extern IA64FAULT vcpu_set_ibr(VCPU *vcpu,UINT64 reg,UINT64 val);
extern IA64FAULT vcpu_set_dbr(VCPU *vcpu,UINT64 reg,UINT64 val);
extern IA64FAULT vcpu_get_ibr(VCPU *vcpu,UINT64 reg,UINT64 *pval);
extern IA64FAULT vcpu_get_dbr(VCPU *vcpu,UINT64 reg,UINT64 *pval);
/* performance monitor registers */
extern IA64FAULT vcpu_set_pmc(VCPU *vcpu,UINT64 reg,UINT64 val);
extern IA64FAULT vcpu_set_pmd(VCPU *vcpu,UINT64 reg,UINT64 val);
extern IA64FAULT vcpu_get_pmc(VCPU *vcpu,UINT64 reg,UINT64 *pval);
extern IA64FAULT vcpu_get_pmd(VCPU *vcpu,UINT64 reg,UINT64 *pval);
/* banked general registers */
extern IA64FAULT vcpu_bsw0(VCPU *vcpu);
extern IA64FAULT vcpu_bsw1(VCPU *vcpu);
/* region registers */
extern IA64FAULT vcpu_set_rr(VCPU *vcpu,UINT64 reg,UINT64 val);
extern IA64FAULT vcpu_get_rr(VCPU *vcpu,UINT64 reg,UINT64 *pval);
extern IA64FAULT vcpu_get_rr_ve(VCPU *vcpu,UINT64 vadr);
/* protection key registers */
extern IA64FAULT vcpu_get_pkr(VCPU *vcpu, UINT64 reg, UINT64 *pval);
extern IA64FAULT vcpu_set_pkr(VCPU *vcpu, UINT64 reg, UINT64 val);
extern IA64FAULT vcpu_tak(VCPU *vcpu, UINT64 vadr, UINT64 *key);
/* TLB */
extern void vcpu_purge_tr_entry(TR_ENTRY *trp);
extern IA64FAULT vcpu_itr_d(VCPU *vcpu, UINT64 slot, UINT64 padr,
		UINT64 itir, UINT64 ifa);
extern IA64FAULT vcpu_itr_i(VCPU *vcpu, UINT64 slot, UINT64 padr,
		UINT64 itir, UINT64 ifa);
extern IA64FAULT vcpu_itc_d(VCPU *vcpu, UINT64 padr, UINT64 itir, UINT64 ifa);
extern IA64FAULT vcpu_itc_i(VCPU *vcpu, UINT64 padr, UINT64 itir, UINT64 ifa);
extern IA64FAULT vcpu_ptc_l(VCPU *vcpu, UINT64 vadr, UINT64 addr_range);
extern IA64FAULT vcpu_ptc_e(VCPU *vcpu, UINT64 vadr);
extern IA64FAULT vcpu_ptc_g(VCPU *vcpu, UINT64 vadr, UINT64 addr_range);
extern IA64FAULT vcpu_ptc_ga(VCPU *vcpu, UINT64 vadr, UINT64 addr_range);
extern IA64FAULT vcpu_ptr_d(VCPU *vcpu,UINT64 vadr, UINT64 addr_range);
extern IA64FAULT vcpu_ptr_i(VCPU *vcpu,UINT64 vadr, UINT64 addr_range);
extern IA64FAULT vcpu_translate(VCPU *vcpu, UINT64 address,
				BOOLEAN is_data, BOOLEAN in_tpa,
				UINT64 *pteval, UINT64 *itir, UINT64 *iha);
extern IA64FAULT vcpu_tpa(VCPU *vcpu, UINT64 vadr, UINT64 *padr);
extern IA64FAULT vcpu_force_data_miss(VCPU *vcpu, UINT64 ifa);
extern IA64FAULT vcpu_fc(VCPU *vcpu, UINT64 vadr);
/* misc */
extern IA64FAULT vcpu_rfi(VCPU *vcpu);
extern IA64FAULT vcpu_thash(VCPU *vcpu, UINT64 vadr, UINT64 *pval);
extern IA64FAULT vcpu_cover(VCPU *vcpu);
extern IA64FAULT vcpu_ttag(VCPU *vcpu, UINT64 vadr, UINT64 *padr);
extern IA64FAULT vcpu_get_cpuid(VCPU *vcpu, UINT64 reg, UINT64 *pval);

extern void vcpu_pend_interrupt(VCPU *vcpu, UINT64 vector);
extern void vcpu_pend_timer(VCPU *vcpu);
extern void vcpu_poke_timer(VCPU *vcpu);
extern void vcpu_set_next_timer(VCPU *vcpu);
extern BOOLEAN vcpu_timer_expired(VCPU *vcpu);
extern UINT64 vcpu_deliverable_interrupts(VCPU *vcpu);
extern void vcpu_itc_no_srlz(VCPU *vcpu, UINT64, UINT64, UINT64, UINT64, UINT64);
extern UINT64 vcpu_get_tmp(VCPU *, UINT64);
extern void vcpu_set_tmp(VCPU *, UINT64, UINT64);

static inline UINT64
itir_ps(UINT64 itir)
{
    return ((itir >> 2) & 0x3f);
}

static inline UINT64
itir_mask(UINT64 itir)
{
    return (~((1UL << itir_ps(itir)) - 1));
}

#define verbose(a...) do {if (vcpu_verbose) printf(a);} while(0)

//#define vcpu_quick_region_check(_tr_regions,_ifa) 1
#define vcpu_quick_region_check(_tr_regions,_ifa)           \
    (_tr_regions & (1 << ((unsigned long)_ifa >> 61)))
#define vcpu_quick_region_set(_tr_regions,_ifa)             \
    do {_tr_regions |= (1 << ((unsigned long)_ifa >> 61)); } while (0)


#endif
