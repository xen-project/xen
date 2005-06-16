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
    u32  tsc_bits;      /* 0: 32 bits read from the CPU's TSC. */
    u32  tsc_bitshift;  /* 4: 'tsc_bits' uses N:N+31 of TSC.   */
} PACKED tsc_timestamp_t; /* 8 bytes */

#include <asm/tlb.h>	/* TR_ENTRY */

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
//} PACKED arch_vcpu_info_t;
} arch_vcpu_info_t;		// DON'T PACK 

typedef struct {
	int evtchn_vector;
	int domain_controller_evtchn;
	unsigned int flags;
//} PACKED arch_shared_info_t;
} arch_shared_info_t;		// DON'T PACK 

/*
 * The following is all CPU context. Note that the i387_ctxt block is filled 
 * in by FXSAVE if the CPU has feature FXSR; otherwise FSAVE is used.
 */
#include <asm/ptrace.h>
typedef struct vcpu_guest_context {
	struct pt_regs regs;
	arch_vcpu_info_t vcpu;
	arch_shared_info_t shared;
} PACKED vcpu_guest_context_t;

#endif /* !__ASSEMBLY__ */

#define	XEN_HYPER_RFI			1
#define	XEN_HYPER_RSM_DT		2
#define	XEN_HYPER_SSM_DT		3
#define	XEN_HYPER_COVER			4
#define	XEN_HYPER_ITC_D			5
#define	XEN_HYPER_ITC_I			6
#define	XEN_HYPER_SSM_I			7

#endif /* __HYPERVISOR_IF_IA64_H__ */
