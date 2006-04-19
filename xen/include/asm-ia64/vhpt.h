#ifndef ASM_VHPT_H
#define ASM_VHPT_H

#define VHPT_ENABLED 1
#define VHPT_ENABLED_REGION_0_TO_6 1
#define VHPT_ENABLED_REGION_7 0

/* Size of the VHPT.  */
#define	VHPT_SIZE_LOG2			24

/* Number of entries in the VHPT.  The size of an entry is 4*8B == 32B */
#define	VHPT_NUM_ENTRIES		(1 << (VHPT_SIZE_LOG2 - 5))

#define	VHPT_PAGE_SHIFT			VHPT_SIZE_LOG2

#ifdef CONFIG_SMP
# define vhpt_flush_all()	smp_vhpt_flush_all()
#else
# define vhpt_flush_all()	vhpt_flush()
#endif
// FIXME: These should be automatically generated

#define	VLE_PGFLAGS_OFFSET		0
#define	VLE_ITIR_OFFSET			8
#define	VLE_TITAG_OFFSET		16
#define	VLE_CCHAIN_OFFSET		24

#ifndef __ASSEMBLY__
//
// VHPT Long Format Entry (as recognized by hw)
//
struct vhpt_lf_entry {
    unsigned long page_flags;
    unsigned long itir;
    unsigned long ti_tag;
    unsigned long CChain;
};

#define INVALID_TI_TAG 0x8000000000000000L

extern void vhpt_init (void);
extern void zero_vhpt_stats(void);
extern int dump_vhpt_stats(char *buf);
extern void vhpt_flush_address(unsigned long vadr, unsigned long addr_range);
extern void vhpt_flush_address_remote(int cpu, unsigned long vadr,
				      unsigned long addr_range);
extern void vhpt_multiple_insert(unsigned long vaddr, unsigned long pte,
				 unsigned long logps);
extern void vhpt_insert (unsigned long vadr, unsigned long ptr,
			 unsigned logps);
extern void vhpt_flush(void);
extern void smp_vhpt_flush_all(void);

/* Currently the VHPT is allocated per CPU.  */
DECLARE_PER_CPU (unsigned long, vhpt_paddr);
DECLARE_PER_CPU (unsigned long, vhpt_pend);

#endif /* !__ASSEMBLY */

#if !VHPT_ENABLED
#define VHPT_CCHAIN_LOOKUP(Name, i_or_d)
#else

// VHPT_CCHAIN_LOOKUP is intended to run with psr.i+ic off
#define VHPT_CCHAIN_LOOKUP(Name, i_or_d) 			\
								\
CC_##Name:;							\
	mov r31 = pr;						\
	mov r16 = cr.ifa;					\
	;;							\
	extr.u r17=r16,59,5					\
	;;							\
	/* If address belongs to VMM, go to alt tlb handler */	\
	cmp.eq p6,p0=0x1e,r17;					\
(p6)	br.cond.spnt	late_alt_##Name				\
	;;							\
	cmp.eq p6,p0=0x1d,r17;					\
(p6)	br.cond.spnt	late_alt_##Name				\
	;;							\
	mov pr = r31, 0x1ffff;					\
	;;							


/* r16 = vadr, r26 = pte, r27 = logps */ 
#define VHPT_INSERT()					\
	{.mmi;						\
		thash r17 = r16;			\
		or r26 = 1, r26;			\
		nop 0;					\
		;;					\
	};						\
	{.mii;						\
		ttag r21 = r16;				\
		adds r18 = VLE_ITIR_OFFSET, r17;	\
		adds r19 = VLE_PGFLAGS_OFFSET, r17;	\
		;;					\
	};						\
	{.mmi;						\
							\
		st8[r18] = r27;				\
		adds r20 = VLE_TITAG_OFFSET, r17;	\
		nop 0;					\
		;;					\
	};						\
	{.mmb;						\
		st8[r19] = r26;				\
		st8[r20] = r21;				\
		nop 0;					\
		;;					\
	}


#endif	/* VHPT_ENABLED */
#endif
