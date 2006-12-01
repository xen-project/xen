#ifndef _ASM_ELF_H__
#define _ASM_ELF_H__

#include <xen/lib.h>       /* for printk() used in stub */

typedef struct {
    unsigned long dummy;
} ELF_Gregset;

typedef struct {
    unsigned long dummy;
} crash_xen_core_t;

static inline void elf_core_save_regs(ELF_Gregset *core_regs, 
                                      crash_xen_core_t *xen_core_regs)
{
    printk("STUB: " __FILE__ ": %s: not implemented\n", __FUNCTION__);
}

#endif /* _ASM_ELF_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
