/******************************************************************************
 * physdev.h
 */

#ifndef __XEN_PHYSDEV_H__
#define __XEN_PHYSDEV_H__

#include <public/physdev.h>

void physdev_modify_ioport_access_range( struct domain *d, int enable, 
                                 int port, int num );
void physdev_destroy_state(struct domain *d);
int physdev_pci_access_modify(domid_t dom, int bus, int dev, int func, 
                              int enable);
int domain_iomem_in_pfn(struct domain *p, unsigned long pfn);
long do_physdev_op(physdev_op_t *uop);
void physdev_init_dom0(struct domain *d);

#endif /* __XEN_PHYSDEV_H__ */
