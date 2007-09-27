#ifndef __IA64_ELF_H__
#define __IA64_ELF_H__

typedef struct {
    unsigned long r1;
    unsigned long r2;
    unsigned long r13;
    unsigned long cr_iip;
    unsigned long ar_rsc;
    unsigned long r30;
    unsigned long ar_bspstore;
    unsigned long ar_rnat;
    unsigned long ar_ccv;
    unsigned long ar_unat;
    unsigned long ar_pfs;
    unsigned long r31;
    unsigned long ar_csd;
    unsigned long ar_ssd;
} ELF_Gregset;

/*
 * elf_gregset_t contains the application-level state in the following order:
 *	r0-r31
 *	NaT bits (for r0-r31; bit N == 1 iff rN is a NaT)
 *	predicate registers (p0-p63)
 *	b0-b7
 *	ip cfm psr
 *	ar.rsc ar.bsp ar.bspstore ar.rnat
 *	ar.ccv ar.unat ar.fpsr ar.pfs ar.lc ar.ec ar.csd ar.ssd
 */
#define ELF_NGREG	128 /* we really need just 72,
			     * but let's leave some headroom */

typedef unsigned long elf_greg_t;
typedef elf_greg_t elf_gregset_t[ELF_NGREG];
typedef elf_gregset_t crash_xen_core_t;

extern void ia64_elf_core_copy_regs (struct pt_regs *src, elf_gregset_t dst);

static inline void elf_core_save_regs(ELF_Gregset *core_regs, 
                                      crash_xen_core_t *xen_core_regs)
{
    ia64_elf_core_copy_regs(NULL, *xen_core_regs);
}

#endif /* __IA64_ELF_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
