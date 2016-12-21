/**
 * @file op_model_athlon.h
 * athlon / K7 model-specific MSR operations
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author Philippe Elie
 * @author Graydon Hoare
 */

#include <xen/types.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/apic.h>
#include <asm/processor.h>
#include <xen/xenoprof.h>
#include <asm/regs.h>
#include <asm/current.h>
#include <asm/hvm/support.h>
#include <xen/pci_regs.h>
#include <xen/pci_ids.h>

#include "op_x86_model.h"
#include "op_counter.h"

#define K7_NUM_COUNTERS 4
#define K7_NUM_CONTROLS 4

#define FAM15H_NUM_COUNTERS 6
#define FAM15H_NUM_CONTROLS 6

#define MAX_COUNTERS FAM15H_NUM_COUNTERS

#define CTR_READ(msr_content,msrs,c) do {rdmsrl(msrs->counters[(c)].addr, (msr_content));} while (0)
#define CTR_WRITE(l,msrs,c) do {wrmsr(msrs->counters[(c)].addr, -(unsigned int)(l), -1);} while (0)
#define CTR_OVERFLOWED(n) (!((n) & (1ULL<<31)))

#define CTRL_READ(msr_content,msrs,c) do {rdmsrl(msrs->controls[(c)].addr, (msr_content));} while (0)
#define CTRL_WRITE(msr_content,msrs,c) do {wrmsrl(msrs->controls[(c)].addr, (msr_content));} while (0)
#define CTRL_SET_ACTIVE(n) (n |= (1ULL<<22))
#define CTRL_SET_INACTIVE(n) (n &= ~(1ULL<<22))
#define CTRL_CLEAR(val) (val &= (1ULL<<21))
#define CTRL_SET_ENABLE(val) (val |= 1ULL<<20)
#define CTRL_SET_USR(val,u) (val |= ((u & 1) << 16))
#define CTRL_SET_KERN(val,k) (val |= ((k & 1) << 17))
#define CTRL_SET_UM(val, m) (val |= ((m & 0xff) << 8))
#define CTRL_SET_EVENT(val, e) (val |= (((e >> 8) & 0xf) | (e & 0xff)))
#define CTRL_SET_HOST_ONLY(val, h) (val |= ((h & 0x1ULL) << 41))
#define CTRL_SET_GUEST_ONLY(val, h) (val |= ((h & 0x1ULL) << 40))

static unsigned long reset_value[MAX_COUNTERS];

extern char svm_stgi_label[];

u32 ibs_caps = 0;
static u64 ibs_op_ctl;

/* IBS cpuid feature detection */
#define IBS_CPUID_FEATURES              0x8000001b

/* IBS MSRs */
#define MSR_AMD64_IBSFETCHCTL           0xc0011030
#define MSR_AMD64_IBSFETCHLINAD         0xc0011031
#define MSR_AMD64_IBSFETCHPHYSAD        0xc0011032
#define MSR_AMD64_IBSOPCTL              0xc0011033
#define MSR_AMD64_IBSOPRIP              0xc0011034
#define MSR_AMD64_IBSOPDATA             0xc0011035
#define MSR_AMD64_IBSOPDATA2            0xc0011036
#define MSR_AMD64_IBSOPDATA3            0xc0011037
#define MSR_AMD64_IBSDCLINAD            0xc0011038
#define MSR_AMD64_IBSDCPHYSAD           0xc0011039
#define MSR_AMD64_IBSCTL                0xc001103a

/*
 * Same bit mask as for IBS cpuid feature flags (Fn8000_001B_EAX), but
 * bit 0 is used to indicate the existence of IBS.
 */
#define IBS_CAPS_AVAIL                  (1LL<<0)
#define IBS_CAPS_RDWROPCNT              (1LL<<3)
#define IBS_CAPS_OPCNT                  (1LL<<4)

/* IBS randomization macros */
#define IBS_RANDOM_BITS                 12
#define IBS_RANDOM_MASK                 ((1ULL << IBS_RANDOM_BITS) - 1)
#define IBS_RANDOM_MAXCNT_OFFSET        (1ULL << (IBS_RANDOM_BITS - 5))

/* IbsFetchCtl bits/masks */
#define IBS_FETCH_RAND_EN               (1ULL<<57)
#define IBS_FETCH_VAL                   (1ULL<<49)
#define IBS_FETCH_ENABLE                (1ULL<<48)
#define IBS_FETCH_CNT                   0xFFFF0000ULL
#define IBS_FETCH_MAX_CNT               0x0000FFFFULL

/* IbsOpCtl bits */
#define IBS_OP_CNT_CTL                  (1ULL<<19)
#define IBS_OP_VAL                      (1ULL<<18)
#define IBS_OP_ENABLE                   (1ULL<<17)
#define IBS_OP_MAX_CNT                  0x0000FFFFULL

/* IBS sample identifier */
#define IBS_FETCH_CODE                  13
#define IBS_OP_CODE                     14

#define clamp(val, min, max) ({			\
	typeof(val) __val = (val);		\
	typeof(min) __min = (min);		\
	typeof(max) __max = (max);		\
	(void) (&__val == &__min);		\
	(void) (&__val == &__max);		\
	__val = __val < __min ? __min: __val;	\
	__val > __max ? __max: __val; })

/*
 * 16-bit Linear Feedback Shift Register (LFSR)
 */
static unsigned int lfsr_random(void)
{
    static unsigned int lfsr_value = 0xF00D;
    unsigned int bit;

    /* Compute next bit to shift in */
    bit = ((lfsr_value >> 0) ^
           (lfsr_value >> 2) ^
           (lfsr_value >> 3) ^
           (lfsr_value >> 5)) & 0x0001;

    /* Advance to next register value */
    lfsr_value = (lfsr_value >> 1) | (bit << 15);

    return lfsr_value;
}

/*
 * IBS software randomization
 *
 * The IBS periodic op counter is randomized in software. The lower 12
 * bits of the 20 bit counter are randomized. IbsOpCurCnt is
 * initialized with a 12 bit random value.
 */
static inline u64 op_amd_randomize_ibs_op(u64 val)
{
    unsigned int random = lfsr_random();

    if (!(ibs_caps & IBS_CAPS_RDWROPCNT))
        /*
         * Work around if the hw can not write to IbsOpCurCnt
         *
         * Randomize the lower 8 bits of the 16 bit
         * IbsOpMaxCnt [15:0] value in the range of -128 to
         * +127 by adding/subtracting an offset to the
         * maximum count (IbsOpMaxCnt).
         *
         * To avoid over or underflows and protect upper bits
         * starting at bit 16, the initial value for
         * IbsOpMaxCnt must fit in the range from 0x0081 to
         * 0xff80.
         */
        val += (s8)(random >> 4);
    else
        val |= (u64)(random & IBS_RANDOM_MASK) << 32;

    return val;
}

static void athlon_fill_in_addresses(struct op_msrs * const msrs)
{
	msrs->counters[0].addr = MSR_K7_PERFCTR0;
	msrs->counters[1].addr = MSR_K7_PERFCTR1;
	msrs->counters[2].addr = MSR_K7_PERFCTR2;
	msrs->counters[3].addr = MSR_K7_PERFCTR3;

	msrs->controls[0].addr = MSR_K7_EVNTSEL0;
	msrs->controls[1].addr = MSR_K7_EVNTSEL1;
	msrs->controls[2].addr = MSR_K7_EVNTSEL2;
	msrs->controls[3].addr = MSR_K7_EVNTSEL3;
}

static void fam15h_fill_in_addresses(struct op_msrs * const msrs)
{
	msrs->counters[0].addr = MSR_AMD_FAM15H_PERFCTR0;
	msrs->counters[1].addr = MSR_AMD_FAM15H_PERFCTR1;
	msrs->counters[2].addr = MSR_AMD_FAM15H_PERFCTR2;
	msrs->counters[3].addr = MSR_AMD_FAM15H_PERFCTR3;
	msrs->counters[4].addr = MSR_AMD_FAM15H_PERFCTR4;
	msrs->counters[5].addr = MSR_AMD_FAM15H_PERFCTR5;

	msrs->controls[0].addr = MSR_AMD_FAM15H_EVNTSEL0;
	msrs->controls[1].addr = MSR_AMD_FAM15H_EVNTSEL1;
	msrs->controls[2].addr = MSR_AMD_FAM15H_EVNTSEL2;
	msrs->controls[3].addr = MSR_AMD_FAM15H_EVNTSEL3;
	msrs->controls[4].addr = MSR_AMD_FAM15H_EVNTSEL4;
	msrs->controls[5].addr = MSR_AMD_FAM15H_EVNTSEL5;
}

static void athlon_setup_ctrs(struct op_msrs const * const msrs)
{
	uint64_t msr_content;
	int i;
	unsigned int const nr_ctrs = model->num_counters;
	unsigned int const nr_ctrls = model->num_controls;
 
	/* clear all counters */
	for (i = 0 ; i < nr_ctrls; ++i) {
		CTRL_READ(msr_content, msrs, i);
		CTRL_CLEAR(msr_content);
		CTRL_WRITE(msr_content, msrs, i);
	}
	
	/* avoid a false detection of ctr overflows in NMI handler */
	for (i = 0; i < nr_ctrs; ++i) {
		CTR_WRITE(1, msrs, i);
	}

	/* enable active counters */
	for (i = 0; i < nr_ctrs; ++i) {
		if (counter_config[i].enabled) {
			reset_value[i] = counter_config[i].count;

			CTR_WRITE(counter_config[i].count, msrs, i);

			CTRL_READ(msr_content, msrs, i);
			CTRL_CLEAR(msr_content);
			CTRL_SET_ENABLE(msr_content);
			CTRL_SET_USR(msr_content, counter_config[i].user);
			CTRL_SET_KERN(msr_content, counter_config[i].kernel);
			CTRL_SET_UM(msr_content, counter_config[i].unit_mask);
			CTRL_SET_EVENT(msr_content, counter_config[i].event);
			CTRL_SET_HOST_ONLY(msr_content, 0);
			CTRL_SET_GUEST_ONLY(msr_content, 0);
			CTRL_WRITE(msr_content, msrs, i);
		} else {
			reset_value[i] = 0;
		}
	}
}

static inline void
ibs_log_event(u64 data, struct cpu_user_regs const * const regs, int mode)
{
	struct vcpu *v = current;
	u32 temp = 0;

	temp = data & 0xFFFFFFFF;
	xenoprof_log_event(v, regs, temp, mode, 0);
	
	temp = (data >> 32) & 0xFFFFFFFF;
	xenoprof_log_event(v, regs, temp, mode, 0);
	
}

static inline int handle_ibs(int mode, struct cpu_user_regs const * const regs)
{
	u64 val, ctl;
	struct vcpu *v = current;

	if (!ibs_caps)
		return 1;

	if (ibs_config.fetch_enabled) {
		rdmsrl(MSR_AMD64_IBSFETCHCTL, ctl);
		if (ctl & IBS_FETCH_VAL) {
			rdmsrl(MSR_AMD64_IBSFETCHLINAD, val);
			xenoprof_log_event(v, regs, IBS_FETCH_CODE, mode, 0);
			xenoprof_log_event(v, regs, val, mode, 0);

			ibs_log_event(val, regs, mode);
			ibs_log_event(ctl, regs, mode);

			rdmsrl(MSR_AMD64_IBSFETCHPHYSAD, val);
			ibs_log_event(val, regs, mode);
		
			/* reenable the IRQ */
			ctl &= ~(IBS_FETCH_VAL | IBS_FETCH_CNT);
			ctl |= IBS_FETCH_ENABLE;
			wrmsrl(MSR_AMD64_IBSFETCHCTL, ctl);
		}
	}

	if (ibs_config.op_enabled) {
		rdmsrl(MSR_AMD64_IBSOPCTL, ctl);
		if (ctl & IBS_OP_VAL) {

			rdmsrl(MSR_AMD64_IBSOPRIP, val);
			xenoprof_log_event(v, regs, IBS_OP_CODE, mode, 0);
			xenoprof_log_event(v, regs, val, mode, 0);
			
			ibs_log_event(val, regs, mode);

			rdmsrl(MSR_AMD64_IBSOPDATA, val);
			ibs_log_event(val, regs, mode);
			rdmsrl(MSR_AMD64_IBSOPDATA2, val);
			ibs_log_event(val, regs, mode);
			rdmsrl(MSR_AMD64_IBSOPDATA3, val);
			ibs_log_event(val, regs, mode);
			rdmsrl(MSR_AMD64_IBSDCLINAD, val);
			ibs_log_event(val, regs, mode);
			rdmsrl(MSR_AMD64_IBSDCPHYSAD, val);
			ibs_log_event(val, regs, mode);

			/* reenable the IRQ */
			ctl = op_amd_randomize_ibs_op(ibs_op_ctl);
			wrmsrl(MSR_AMD64_IBSOPCTL, ctl);
		}
	}

    return 1;
}

static int athlon_check_ctrs(unsigned int const cpu,
			     struct op_msrs const * const msrs,
			     struct cpu_user_regs const * const regs)

{
	uint64_t msr_content;
	int i;
	int ovf = 0;
	unsigned long eip = regs->rip;
	int mode = 0;
	struct vcpu *v = current;
	struct cpu_user_regs *guest_regs = guest_cpu_user_regs();
	unsigned int const nr_ctrs = model->num_counters;

	if (!guest_mode(regs) &&
	    (eip == (unsigned long)svm_stgi_label)) {
		/* SVM guest was running when NMI occurred */
		ASSERT(is_hvm_vcpu(v));
		eip = guest_regs->rip;
		mode = xenoprofile_get_mode(v, guest_regs);
	} else
		mode = xenoprofile_get_mode(v, regs);

	for (i = 0 ; i < nr_ctrs; ++i) {
		CTR_READ(msr_content, msrs, i);
		if (CTR_OVERFLOWED(msr_content)) {
			xenoprof_log_event(current, regs, eip, mode, i);
			CTR_WRITE(reset_value[i], msrs, i);
			ovf = 1;
		}
	}

	ovf = handle_ibs(mode, regs);
	/* See op_model_ppro.c */
	return ovf;
}

static inline void start_ibs(void)
{
	u64 val = 0;

	if (!ibs_caps)
		return;

	if (ibs_config.fetch_enabled) {
		val = (ibs_config.max_cnt_fetch >> 4) & IBS_FETCH_MAX_CNT;
		val |= ibs_config.rand_en ? IBS_FETCH_RAND_EN : 0;
		val |= IBS_FETCH_ENABLE;
		wrmsrl(MSR_AMD64_IBSFETCHCTL, val);
	}

	if (ibs_config.op_enabled) {
		ibs_op_ctl = ibs_config.max_cnt_op >> 4;
		if (!(ibs_caps & IBS_CAPS_RDWROPCNT)) {
			/*
			 * IbsOpCurCnt not supported.  See
			 * op_amd_randomize_ibs_op() for details.
			 */
			ibs_op_ctl = clamp((unsigned long long)ibs_op_ctl, 
							0x0081ULL, 0xFF80ULL);
		} else {
			/*
			 * The start value is randomized with a
			 * positive offset, we need to compensate it
			 * with the half of the randomized range. Also
			 * avoid underflows.
			 */
		ibs_op_ctl = min(ibs_op_ctl + IBS_RANDOM_MAXCNT_OFFSET,
					IBS_OP_MAX_CNT);
		}
		if (ibs_caps & IBS_CAPS_OPCNT && ibs_config.dispatched_ops)
			ibs_op_ctl |= IBS_OP_CNT_CTL;
		ibs_op_ctl |= IBS_OP_ENABLE;
		val = op_amd_randomize_ibs_op(ibs_op_ctl);
		wrmsrl(MSR_AMD64_IBSOPCTL, val);
	}
}
 
static void athlon_start(struct op_msrs const * const msrs)
{
	uint64_t msr_content;
	int i;
	unsigned int const nr_ctrs = model->num_counters;
	for (i = 0 ; i < nr_ctrs ; ++i) {
		if (reset_value[i]) {
			CTRL_READ(msr_content, msrs, i);
			CTRL_SET_ACTIVE(msr_content);
			CTRL_WRITE(msr_content, msrs, i);
		}
	}
	start_ibs();
}

static void stop_ibs(void)
{
	if (!ibs_caps)
		return;

	if (ibs_config.fetch_enabled)
		/* clear max count and enable */
		wrmsrl(MSR_AMD64_IBSFETCHCTL, 0);

	if (ibs_config.op_enabled)
		/* clear max count and enable */
		wrmsrl(MSR_AMD64_IBSOPCTL, 0);
}

static void athlon_stop(struct op_msrs const * const msrs)
{
	uint64_t msr_content;
	int i;
	unsigned int const nr_ctrs = model->num_counters;

	/* Subtle: stop on all counters to avoid race with
	 * setting our pm callback */
	for (i = 0 ; i < nr_ctrs ; ++i) {
		CTRL_READ(msr_content, msrs, i);
		CTRL_SET_INACTIVE(msr_content);
		CTRL_WRITE(msr_content, msrs, i);
	}

	stop_ibs();
}

#define IBSCTL_LVTOFFSETVAL             (1 << 8)
#define APIC_EILVT_MSG_NMI              0x4
#define APIC_EILVT_LVTOFF_IBS           1
#define APIC_EILVTn(n)                  (0x500 + 0x10 * n)
static inline void __init init_ibs_nmi_per_cpu(void *arg)
{
	unsigned long reg;

	reg = (APIC_EILVT_LVTOFF_IBS << 4) + APIC_EILVTn(0);
	apic_write(reg, APIC_EILVT_MSG_NMI << 8);
}

#define PCI_DEVICE_ID_AMD_10H_NB_MISC   0x1203
#define IBSCTL                          0x1cc
static int __init init_ibs_nmi(void)
{
	int bus, dev, func;
	u32 id, value;
	u16 vendor_id, dev_id;
	int nodes;

	/* per CPU setup */
	on_each_cpu(init_ibs_nmi_per_cpu, NULL, 1);

	nodes = 0;
	for (bus = 0; bus < 256; bus++) {
		for (dev = 0; dev < 32; dev++) {
			for (func = 0; func < 8; func++) {
				id = pci_conf_read32(0, bus, dev, func, PCI_VENDOR_ID);

				vendor_id = id & 0xffff;
				dev_id = (id >> 16) & 0xffff;

				if ((vendor_id == PCI_VENDOR_ID_AMD) &&
					(dev_id == PCI_DEVICE_ID_AMD_10H_NB_MISC)) {

					pci_conf_write32(0, bus, dev, func, IBSCTL,
						IBSCTL_LVTOFFSETVAL | APIC_EILVT_LVTOFF_IBS);

					value = pci_conf_read32(0, bus, dev, func, IBSCTL);

					if (value != (IBSCTL_LVTOFFSETVAL |
						APIC_EILVT_LVTOFF_IBS)) {
						printk("Xenoprofile: Failed to setup IBS LVT offset, "
							"IBSCTL = %#x\n", value);
						return 1;
					}
					nodes++;
				}
			}
		}
	}

	if (!nodes) {
		printk("Xenoprofile: No CPU node configured for IBS\n");
		return 1;
	}

	return 0;
}

static void __init get_ibs_caps(void)
{
	if (!boot_cpu_has(X86_FEATURE_IBS))
		return;

    /* check IBS cpuid feature flags */
	if (current_cpu_data.extended_cpuid_level >= IBS_CPUID_FEATURES)
		ibs_caps = cpuid_eax(IBS_CPUID_FEATURES);
	if (!(ibs_caps & IBS_CAPS_AVAIL))
		/* cpuid flags not valid */
		ibs_caps = 0;
}

void __init ibs_init(void)
{
	get_ibs_caps();

	if ( !ibs_caps )
		return;

	if (init_ibs_nmi()) {
		ibs_caps = 0;
		return;
	}

	printk("Xenoprofile: AMD IBS detected (%#x)\n",
		(unsigned)ibs_caps);
}

struct op_x86_model_spec const op_athlon_spec = {
	.num_counters = K7_NUM_COUNTERS,
	.num_controls = K7_NUM_CONTROLS,
	.fill_in_addresses = &athlon_fill_in_addresses,
	.setup_ctrs = &athlon_setup_ctrs,
	.check_ctrs = &athlon_check_ctrs,
	.start = &athlon_start,
	.stop = &athlon_stop
};

struct op_x86_model_spec const op_amd_fam15h_spec = {
	.num_counters = FAM15H_NUM_COUNTERS,
	.num_controls = FAM15H_NUM_CONTROLS,
	.fill_in_addresses = &fam15h_fill_in_addresses,
	.setup_ctrs = &athlon_setup_ctrs,
	.check_ctrs = &athlon_check_ctrs,
	.start = &athlon_start,
	.stop = &athlon_stop
};
