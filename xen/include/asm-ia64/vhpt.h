#ifndef ASM_VHPT_H
#define ASM_VHPT_H

#define VHPT_ENABLED 1

/* Size of the VHPT.  */
#ifdef CONFIG_XEN_IA64_DOM0_VP
// XXX work around to avoid trigerring xenLinux software lock up detection.
# define	VHPT_SIZE_LOG2			16	// 64KB
#else
# define	VHPT_SIZE_LOG2			24	// 16MB default
#endif

/* Number of entries in the VHPT.  The size of an entry is 4*8B == 32B */
#define	VHPT_NUM_ENTRIES		(1 << (VHPT_SIZE_LOG2 - 5))

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
extern void vhpt_insert (unsigned long vadr, unsigned long pte,
			 unsigned long logps);
extern void vhpt_flush(void);
extern void smp_vhpt_flush_all(void);

/* Currently the VHPT is allocated per CPU.  */
DECLARE_PER_CPU (unsigned long, vhpt_paddr);
DECLARE_PER_CPU (unsigned long, vhpt_pend);

#endif /* !__ASSEMBLY */
#endif
