/**
 * @file op_x86_model.h
 * interface to x86 model-specific MSR operations
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Graydon Hoare
 */

#ifndef OP_X86_MODEL_H
#define OP_X86_MODEL_H

struct op_msr {
	unsigned long addr;
	uint64_t value;
};

struct op_msrs {
	struct op_msr * counters;
	struct op_msr * controls;
};

struct pt_regs;

/* The model vtable abstracts the differences between
 * various x86 CPU model's perfctr support.
 */
struct op_x86_model_spec {
	unsigned int num_counters;
	unsigned int num_controls;
	void (*fill_in_addresses)(struct op_msrs * const msrs);
	void (*setup_ctrs)(struct op_msrs const * const msrs);
	int (*check_ctrs)(unsigned int const cpu, 
			  struct op_msrs const * const msrs,
			  struct cpu_user_regs const * const regs);
	void (*start)(struct op_msrs const * const msrs);
	void (*stop)(struct op_msrs const * const msrs);
	int (*is_arch_pmu_msr)(u64 msr_index, int *type, int *index);
	int (*allocated_msr)(struct vcpu *v);
	void (*free_msr)(struct vcpu *v);
	void (*load_msr)(struct vcpu * const v, int type, int index, u64 *msr_content);
        void (*save_msr)(struct vcpu * const v, int type, int index, u64 msr_content);
};

extern struct op_x86_model_spec op_ppro_spec;
extern struct op_x86_model_spec op_arch_perfmon_spec;
extern struct op_x86_model_spec const op_p4_spec;
extern struct op_x86_model_spec const op_p4_ht2_spec;
extern struct op_x86_model_spec const op_athlon_spec;
extern struct op_x86_model_spec const op_amd_fam15h_spec;

void arch_perfmon_setup_counters(void);

extern int ppro_has_global_ctrl;
extern struct op_x86_model_spec const *model;

#endif /* OP_X86_MODEL_H */
