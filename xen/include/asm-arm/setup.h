#ifndef __ARM_SETUP_H_
#define __ARM_SETUP_H_

#include <public/version.h>

void copy_from_paddr(void *dst, paddr_t paddr, unsigned long len);

void arch_get_xen_caps(xen_capabilities_info_t *info);

int construct_dom0(struct domain *d);

void init_IRQ(void);

#endif
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
