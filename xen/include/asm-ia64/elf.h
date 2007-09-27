#ifndef __IA64_ELF_H__
#define __IA64_ELF_H__

#include <xen/lib.h>       /* for printk() used in stub */

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

typedef struct {
    unsigned long dummy;
} crash_xen_core_t;

static inline void elf_core_save_regs(ELF_Gregset *core_regs, 
                                      crash_xen_core_t *xen_core_regs)
{
    printk("STUB: " __FILE__ ": %s: not implemented\n", __FUNCTION__);
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
