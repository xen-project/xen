/******************************************************************************
 * arch-ia64/hypervisor-if.h
 * 
 * Guest OS interface to IA64 Xen.
 */

#ifndef __HYPERVISOR_IF_IA64_H__
#define __HYPERVISOR_IF_IA64_H__

// "packed" generates awful code
#define PACKED

/* Pointers are naturally 64 bits in this architecture; no padding needed. */
#define _MEMORY_PADDING(_X)
#define MEMORY_PADDING 

/* Maximum number of virtual CPUs in multi-processor guests. */
/* WARNING: before changing this, check that shared_info fits on a page */
#define MAX_VIRT_CPUS 1

#ifndef __ASSEMBLY__

/* NB. Both the following are 64 bits each. */
typedef unsigned long memory_t;   /* Full-sized pointer/address/memory-size. */

#define MAX_NR_SECTION  32  // at most 32 memory holes
typedef struct {
    unsigned long	start; 	/* start of memory hole */
    unsigned long	end;	/* end of memory hole */
} mm_section_t;

typedef struct {
    unsigned long	mfn : 56;
    unsigned long	type: 8;
} pmt_entry_t;

#define GPFN_MEM		(0UL << 56)	/* Guest pfn is normal mem */
#define GPFN_FRAME_BUFFER	(1UL << 56)	/* VGA framebuffer */
#define GPFN_LOW_MMIO		(2UL << 56)	/* Low MMIO range */
#define GPFN_PIB		(3UL << 56)	/* PIB base */
#define GPFN_IOSAPIC		(4UL << 56)	/* IOSAPIC base */
#define GPFN_LEGACY_IO		(5UL << 56)	/* Legacy I/O base */
#define GPFN_GFW		(6UL << 56)	/* Guest Firmware */
#define GPFN_HIGH_MMIO		(7UL << 56)	/* High MMIO range */

#define GPFN_IO_MASK		(7UL << 56)	/* Guest pfn is I/O type */
#define GPFN_INV_MASK		(31UL << 59)	/* Guest pfn is invalid */

#define INVALID_MFN              (~0UL)


typedef struct
{
} PACKED cpu_user_regs;

/*
 * NB. This may become a 64-bit count with no shift. If this happens then the 
 * structure size will still be 8 bytes, so no other alignments will change.
 */
typedef struct {
    unsigned int  tsc_bits;      /* 0: 32 bits read from the CPU's TSC. */
    unsigned int  tsc_bitshift;  /* 4: 'tsc_bits' uses N:N+31 of TSC.   */
} PACKED tsc_timestamp_t; /* 8 bytes */

struct pt_fpreg {
        union {
                unsigned long bits[2];
                long double __dummy;    /* force 16-byte alignment */
        } u;
};

struct pt_regs {
	/* The following registers are saved by SAVE_MIN: */
	unsigned long b6;		/* scratch */
	unsigned long b7;		/* scratch */

	unsigned long ar_csd;           /* used by cmp8xchg16 (scratch) */
	unsigned long ar_ssd;           /* reserved for future use (scratch) */

	unsigned long r8;		/* scratch (return value register 0) */
	unsigned long r9;		/* scratch (return value register 1) */
	unsigned long r10;		/* scratch (return value register 2) */
	unsigned long r11;		/* scratch (return value register 3) */

	unsigned long cr_ipsr;		/* interrupted task's psr */
	unsigned long cr_iip;		/* interrupted task's instruction pointer */
	unsigned long cr_ifs;		/* interrupted task's function state */

	unsigned long ar_unat;		/* interrupted task's NaT register (preserved) */
	unsigned long ar_pfs;		/* prev function state  */
	unsigned long ar_rsc;		/* RSE configuration */
	/* The following two are valid only if cr_ipsr.cpl > 0: */
	unsigned long ar_rnat;		/* RSE NaT */
	unsigned long ar_bspstore;	/* RSE bspstore */

	unsigned long pr;		/* 64 predicate registers (1 bit each) */
	unsigned long b0;		/* return pointer (bp) */
	unsigned long loadrs;		/* size of dirty partition << 16 */

	unsigned long r1;		/* the gp pointer */
	unsigned long r12;		/* interrupted task's memory stack pointer */
	unsigned long r13;		/* thread pointer */

	unsigned long ar_fpsr;		/* floating point status (preserved) */
	unsigned long r15;		/* scratch */

	/* The remaining registers are NOT saved for system calls.  */

	unsigned long r14;		/* scratch */
	unsigned long r2;		/* scratch */
	unsigned long r3;		/* scratch */

#ifdef CONFIG_VTI
	unsigned long r4;		/* preserved */
	unsigned long r5;		/* preserved */
	unsigned long r6;		/* preserved */
	unsigned long r7;		/* preserved */
	unsigned long cr_iipa;   /* for emulation */
	unsigned long cr_isr;    /* for emulation */
	unsigned long eml_unat;    /* used for emulating instruction */
	unsigned long rfi_pfs;     /* used for elulating rfi */
#endif

	/* The following registers are saved by SAVE_REST: */
	unsigned long r16;		/* scratch */
	unsigned long r17;		/* scratch */
	unsigned long r18;		/* scratch */
	unsigned long r19;		/* scratch */
	unsigned long r20;		/* scratch */
	unsigned long r21;		/* scratch */
	unsigned long r22;		/* scratch */
	unsigned long r23;		/* scratch */
	unsigned long r24;		/* scratch */
	unsigned long r25;		/* scratch */
	unsigned long r26;		/* scratch */
	unsigned long r27;		/* scratch */
	unsigned long r28;		/* scratch */
	unsigned long r29;		/* scratch */
	unsigned long r30;		/* scratch */
	unsigned long r31;		/* scratch */

	unsigned long ar_ccv;		/* compare/exchange value (scratch) */

	/*
	 * Floating point registers that the kernel considers scratch:
	 */
	struct pt_fpreg f6;		/* scratch */
	struct pt_fpreg f7;		/* scratch */
	struct pt_fpreg f8;		/* scratch */
	struct pt_fpreg f9;		/* scratch */
	struct pt_fpreg f10;		/* scratch */
	struct pt_fpreg f11;		/* scratch */
};

typedef struct {
	unsigned long ipsr;
	unsigned long iip;
	unsigned long ifs;
	unsigned long precover_ifs;
	unsigned long isr;
	unsigned long ifa;
	unsigned long iipa;
	unsigned long iim;
	unsigned long unat;  // not sure if this is needed until NaT arch is done
	unsigned long tpr;
	unsigned long iha;
	unsigned long itir;
	unsigned long itv;
	unsigned long pmv;
	unsigned long cmcv;
	unsigned long pta;
	int interrupt_collection_enabled; // virtual psr.ic
	int interrupt_delivery_enabled; // virtual psr.i
	int pending_interruption;
	int incomplete_regframe;	// see SDM vol2 6.8
	unsigned long delivery_mask[4];
	int metaphysical_mode;	// 1 = use metaphys mapping, 0 = use virtual
	int banknum;	// 0 or 1, which virtual register bank is active
	unsigned long bank0_regs[16]; // bank0 regs (r16-r31) when bank1 active
	unsigned long bank1_regs[16]; // bank1 regs (r16-r31) when bank0 active
	unsigned long rrs[8];	// region registers
	unsigned long krs[8];	// kernel registers
	unsigned long pkrs[8];	// protection key registers
	unsigned long tmp[8];	// temp registers (e.g. for hyperprivops)
	int evtchn_vector;
//} PACKED arch_vcpu_info_t;
} arch_vcpu_info_t;		// DON'T PACK 

typedef struct {
	int domain_controller_evtchn;
	unsigned int flags;
//} PACKED arch_shared_info_t;
} arch_shared_info_t;		// DON'T PACK 

typedef struct vcpu_guest_context {
	struct pt_regs regs;
	arch_vcpu_info_t vcpu;
	arch_shared_info_t shared;
} PACKED vcpu_guest_context_t;

#endif /* !__ASSEMBLY__ */

#define	XEN_HYPER_RFI			0x1
#define	XEN_HYPER_RSM_DT		0x2
#define	XEN_HYPER_SSM_DT		0x3
#define	XEN_HYPER_COVER			0x4
#define	XEN_HYPER_ITC_D			0x5
#define	XEN_HYPER_ITC_I			0x6
#define	XEN_HYPER_SSM_I			0x7
#define	XEN_HYPER_GET_IVR		0x8
#define	XEN_HYPER_GET_TPR		0x9
#define	XEN_HYPER_SET_TPR		0xa
#define	XEN_HYPER_EOI			0xb
#define	XEN_HYPER_SET_ITM		0xc
#define	XEN_HYPER_THASH			0xd
#define	XEN_HYPER_PTC_GA		0xe
#define	XEN_HYPER_ITR_D			0xf
#define	XEN_HYPER_GET_RR		0x10
#define	XEN_HYPER_SET_RR		0x11

#endif /* __HYPERVISOR_IF_IA64_H__ */
