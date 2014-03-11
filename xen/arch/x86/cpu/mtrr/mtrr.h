/*
 * local mtrr defines.
 */

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

#define MTRR_CHANGE_MASK_FIXED     0x01
#define MTRR_CHANGE_MASK_VARIABLE  0x02
#define MTRR_CHANGE_MASK_DEFTYPE   0x04


struct mtrr_ops {
	u32	vendor;
	u32	use_intel_if;
//	void	(*init)(void);
	void	(*set)(unsigned int reg, unsigned long base,
		       unsigned long size, mtrr_type type);
	void	(*set_all)(void);

	void	(*get)(unsigned int reg, unsigned long *base,
		       unsigned long *size, mtrr_type * type);
	int	(*get_free_region)(unsigned long base, unsigned long size,
				   int replace_reg);
	int	(*validate_add_page)(unsigned long base, unsigned long size,
				     unsigned int type);
	int	(*have_wrcomb)(void);
};

extern int generic_get_free_region(unsigned long base, unsigned long size,
				   int replace_reg);
extern int generic_validate_add_page(unsigned long base, unsigned long size,
				     unsigned int type);

extern const struct mtrr_ops generic_mtrr_ops;

extern int positive_have_wrcomb(void);

/* library functions for processor-specific routines */
struct set_mtrr_context {
	unsigned long flags;
	unsigned long cr4val;
	uint64_t deftype;
	u32 ccr3;
};

void set_mtrr_done(struct set_mtrr_context *ctxt);
void set_mtrr_cache_disable(struct set_mtrr_context *ctxt);
void set_mtrr_prepare_save(struct set_mtrr_context *ctxt);

void get_mtrr_state(void);

extern void set_mtrr_ops(const struct mtrr_ops *);

extern u64 size_or_mask, size_and_mask;
extern const struct mtrr_ops *mtrr_if;

#define is_cpu(vnd)	(mtrr_if && mtrr_if->vendor == X86_VENDOR_##vnd)
#define use_intel()	(mtrr_if && mtrr_if->use_intel_if == 1)

extern unsigned int num_var_ranges;

void mtrr_state_warn(void);
void mtrr_wrmsr(unsigned int msr, uint64_t msr_content);

extern int amd_init_mtrr(void);
extern int cyrix_init_mtrr(void);
