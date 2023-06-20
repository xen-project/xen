#ifndef __ASM_X86_MTRR_H__
#define __ASM_X86_MTRR_H__

#include <xen/mm.h>

#define MTRR_NUM_TYPES       X86_MT_UCM
#define MEMORY_NUM_TYPES     MTRR_NUM_TYPES
#define NO_HARDCODE_MEM_TYPE MTRR_NUM_TYPES

#define NORMAL_CACHE_MODE          0
#define NO_FILL_CACHE_MODE         2

#define INVALID_MEM_TYPE X86_NUM_MT

/* In the Intel processor's MTRR interface, the MTRR type is always held in
   an 8 bit field: */
typedef u8 mtrr_type;

#define MTRR_PHYSMASK_VALID_BIT  11
#define MTRR_PHYSMASK_VALID      (1 << MTRR_PHYSMASK_VALID_BIT)
#define MTRR_PHYSMASK_SHIFT      12
#define MTRR_PHYSBASE_TYPE_MASK  0xff
#define MTRR_PHYSBASE_SHIFT      12
/* Number of variable range MSR pairs we emulate for HVM guests: */
#define MTRR_VCNT                8
/* Maximum number of variable range MSR pairs if FE is supported. */
#define MTRR_VCNT_MAX            ((MSR_MTRRfix64K_00000 - \
                                   MSR_IA32_MTRR_PHYSBASE(0)) / 2)

struct mtrr_var_range {
	uint64_t base;
	uint64_t mask;
};

#define NUM_FIXED_RANGES 88
#define NUM_FIXED_MSR 11
struct mtrr_state {
	struct mtrr_var_range *var_ranges;
	mtrr_type fixed_ranges[NUM_FIXED_RANGES];
	bool enabled;
	bool fixed_enabled;
	bool have_fixed;
	mtrr_type def_type;

	u64       mtrr_cap;
	/* ranges in var MSRs are overlapped or not:0(no overlapped) */
	bool      overlapped;
};
extern struct mtrr_state mtrr_state;

extern void cf_check mtrr_save_fixed_ranges(void *info);
extern void mtrr_save_state(void);
extern int mtrr_add(unsigned long base, unsigned long size,
                    unsigned int type, char increment);
extern int mtrr_add_page(unsigned long base, unsigned long size,
                         unsigned int type, char increment);
extern int mtrr_del(int reg, unsigned long base, unsigned long size);
extern int mtrr_del_page(int reg, unsigned long base, unsigned long size);
extern int mtrr_get_type(const struct mtrr_state *m, paddr_t pa,
                         unsigned int order);
extern void mtrr_centaur_report_mcr(int mcr, u32 lo, u32 hi);
extern uint32_t get_pat_flags(struct vcpu *v, uint32_t gl1e_flags,
                              paddr_t gpaddr, paddr_t spaddr,
                              uint8_t gmtrr_mtype);
extern uint8_t pat_type_2_pte_flags(uint8_t pat_type);
extern int hold_mtrr_updates_on_aps;
extern void mtrr_aps_sync_begin(void);
extern void mtrr_aps_sync_end(void);
extern void mtrr_bp_restore(void);

extern bool mtrr_var_range_msr_set(struct domain *d, struct mtrr_state *m,
                                   uint32_t msr, uint64_t msr_content);
extern bool mtrr_fix_range_msr_set(struct domain *d, struct mtrr_state *m,
                                   uint32_t row, uint64_t msr_content);
extern bool mtrr_def_type_msr_set(struct domain *d, struct mtrr_state *m,
                                  uint64_t msr_content);
#ifdef CONFIG_HVM
extern void memory_type_changed(struct domain *d);
#else
static inline void memory_type_changed(struct domain *d) {}
#endif

extern bool pat_msr_set(uint64_t *pat, uint64_t msr);

bool is_var_mtrr_overlapped(const struct mtrr_state *m);
bool mtrr_pat_not_equal(const struct vcpu *vd, const struct vcpu *vs);

#endif /* __ASM_X86_MTRR_H__ */
