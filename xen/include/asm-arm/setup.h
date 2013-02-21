#ifndef __ARM_SETUP_H_
#define __ARM_SETUP_H_

#include <public/version.h>

void arch_init_memory(void);

void copy_from_paddr(void *dst, paddr_t paddr, unsigned long len, int attrindx);

void arch_get_xen_caps(xen_capabilities_info_t *info);

int construct_dom0(struct domain *d);

void discard_initial_modules(void);

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
